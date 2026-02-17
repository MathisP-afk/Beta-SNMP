#!/usr/bin/env python3
"""
SNMP Collector Unifié v1.0 - Capture SNMPv2c + SNMPv3
Auteur: Étudiant 1 - Réseaux & Télécoms RT3
Projet: SAE 501-502 - Supervision Réseau
Description: Collecteur SNMP hybride supportant v2c et v3.
             - PASSIF : Scapy capture TOUT le trafic SNMP (v2c + v3)
               (nécessite port mirroring SPAN sur le switch)
             - ACTIF  : polling continu via SNMPv3 GET (optionnel)
             - Envoi à l'API REST (/snmp/v2c/add ou /snmp/v3/add)

Dépendances:
    pip install pysnmp pycryptodomex cryptography requests scapy

Usage:
    # Capture passive v2c uniquement
    python snmp_collector_unified.py -a https://API:8000 -k CLE -i "Ethernet 2"

    # Capture passive v2c+v3 + polling actif v3
    python snmp_collector_unified.py -a https://API:8000 -k CLE -i "Ethernet 2" \\
        -s 10.204.0.119 -u Alleria_W --auth-password Vereesa_W \\
        --priv-password Windrunner -e 80004fb8054d534917e0c200 --poll-interval 60
"""

import asyncio
import hashlib
import datetime
import sys
import argparse
import threading
import queue
import requests
import logging
import time
import re
from typing import Dict, List, Optional
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# IMPORTS OPTIONNELS
# ============================================================================

# pysnmp HLAPI pour le polling actif v3
try:
    from pysnmp.entity import engine, config
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine as HlapiEngine,
        UsmUserData as HlapiUsmUserData,
        UdpTransportTarget as HlapiTarget,
        ContextData as HlapiContextData,
        ObjectType as HlapiObjectType,
        ObjectIdentity as HlapiObjectIdentity,
        get_cmd as hlapi_get_cmd,
    )
    AUTH_SHA = config.USM_AUTH_HMAC96_SHA
    PRIV_DES = config.USM_PRIV_CBC56_DES
    HLAPI_AVAILABLE = True
except ImportError:
    HLAPI_AVAILABLE = False

# Scapy pour capture passive
try:
    from scapy.all import sniff as scapy_sniff, UDP, IP, Raw, conf as scapy_conf
    from scapy.layers.snmp import SNMP
    scapy_conf.sniff_promisc = True
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Crypto pour déchiffrer DES (v3)
try:
    from Cryptodome.Cipher import DES as DES_cipher
    CRYPTO_AVAILABLE = True
except ImportError:
    try:
        from Crypto.Cipher import DES as DES_cipher
        CRYPTO_AVAILABLE = True
    except ImportError:
        CRYPTO_AVAILABLE = False

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTES
# ============================================================================

# Tags ASN.1 context-specific → noms CamelCase (v3 + v2c unifié)
PDU_TYPE_TAGS = {
    0: 'GetRequest',
    1: 'GetNextRequest',
    2: 'Response',
    3: 'SetRequest',
    5: 'GetBulkRequest',
    6: 'InformRequest',
    7: 'Trap',
    8: 'Report',
}

# Mapping Scapy layer names → noms CamelCase normalisés (v2c)
V2C_PDU_MAPPING = {
    'GetRequest': 'GetRequest',
    'SNMPget': 'GetRequest',
    'GetNextRequest': 'GetNextRequest',
    'SNMPnext': 'GetNextRequest',
    'SetRequest': 'SetRequest',
    'SNMPset': 'SetRequest',
    'GetResponse': 'Response',
    'SNMPresponse': 'Response',
    'SNMPtrapv2': 'Trap',
    'SNMPv2_Trap': 'Trap',
    'Trap': 'Trap',
    'GetBulkRequest': 'GetBulkRequest',
    'SNMPbulk': 'GetBulkRequest',
    'InformRequest': 'InformRequest',
}

# Bibliothèque OID (fusionnée v2c + v3)
OID_LIBRARY = {
    '1.3.6.1.2.1.1.1.0': ('sysDescr', 'Description du système'),
    '1.3.6.1.2.1.1.2.0': ('sysObjectID', 'ID Objet Système'),
    '1.3.6.1.2.1.1.3.0': ('sysUpTime', 'Temps de fonctionnement'),
    '1.3.6.1.2.1.1.4.0': ('sysContact', 'Contact administrateur'),
    '1.3.6.1.2.1.1.5.0': ('sysName', 'Nom du système'),
    '1.3.6.1.2.1.1.6.0': ('sysLocation', 'Emplacement physique'),
    '1.3.6.1.2.1.1.7.0': ('sysServices', 'Services offerts'),
    '1.3.6.1.2.1.2.1.0': ('ifNumber', "Nombre d'interfaces"),
    '1.3.6.1.2.1.2.2.1.1': ('ifIndex', 'Index interface'),
    '1.3.6.1.2.1.2.2.1.2': ('ifDescr', 'Description interface'),
    '1.3.6.1.2.1.2.2.1.3': ('ifType', 'Type interface'),
    '1.3.6.1.2.1.2.2.1.5': ('ifSpeed', 'Vitesse interface'),
    '1.3.6.1.2.1.2.2.1.6': ('ifPhysAddress', 'Adresse MAC'),
    '1.3.6.1.2.1.2.2.1.7': ('ifAdminStatus', 'Statut Admin (1=UP, 2=DOWN)'),
    '1.3.6.1.2.1.2.2.1.8': ('ifOperStatus', 'Statut Opérationnel'),
    '1.3.6.1.2.1.2.2.1.10': ('ifInOctets', 'Octets reçus'),
    '1.3.6.1.2.1.2.2.1.16': ('ifOutOctets', 'Octets envoyés'),
    '1.3.6.1.2.1.4.1.0': ('ipForwarding', 'IP Forwarding (1=yes)'),
    '1.3.6.1.2.1.4.20.1.1': ('ipAdEntAddr', 'Adresse IP'),
    '1.3.6.1.6.3.1.1.4.1.0': ('snmpTrapOID', 'OID identifiant le trap'),
    '1.3.6.1.6.3.1.1.5.1': ('coldStart', 'Démarrage à froid'),
    '1.3.6.1.6.3.1.1.5.2': ('warmStart', 'Redémarrage à chaud'),
    '1.3.6.1.6.3.1.1.5.3': ('linkDown', 'Interface désactivée'),
    '1.3.6.1.6.3.1.1.5.4': ('linkUp', 'Interface activée'),
    '1.3.6.1.6.3.1.1.5.5': ('authenticationFailure', "Échec d'authentification"),
    '1.3.6.1.4.1.9.9.43.2.0.1': ('ciscoConfigManEvent', 'Événement config Cisco'),
    '1.3.6.1.2.1.25.1.1.0': ('hrSystemUptime', 'Uptime hôte'),
    '1.3.6.1.2.1.25.2.2.0': ('hrMemorySize', 'Mémoire RAM totale'),
    '1.3.6.1.4.1.2021.4.3.0': ('memTotalSwap', 'Swap Total'),
    '1.3.6.1.4.1.2021.4.5.0': ('memTotalReal', 'RAM Totale'),
    '1.3.6.1.4.1.2021.4.6.0': ('memAvailReal', 'RAM Disponible'),
    '1.3.6.1.4.1.2021.10.1.3.1': ('laLoad.1', 'Load Average 1min'),
    '1.3.6.1.4.1.2021.10.1.3.2': ('laLoad.5', 'Load Average 5min'),
    '1.3.6.1.4.1.2021.10.1.3.3': ('laLoad.15', 'Load Average 15min'),
}

TRAP_TYPE_MAPPING = {
    '1.3.6.1.6.3.1.1.5.1': 'COLD_START',
    '1.3.6.1.6.3.1.1.5.2': 'WARM_START',
    '1.3.6.1.6.3.1.1.5.3': 'LINK_DOWN',
    '1.3.6.1.6.3.1.1.5.4': 'LINK_UP',
    '1.3.6.1.6.3.1.1.5.5': 'AUTH_FAILURE',
}

# OIDs pour le polling actif v3
POLL_OIDS_SYSTEM = [
    '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.3.0',
    '1.3.6.1.2.1.1.4.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0',
    '1.3.6.1.2.1.1.7.0', '1.3.6.1.2.1.2.1.0',
]
POLL_IF_INDICES = [1, 2, 3, 4, 5, 6, 7, 8]
POLL_OIDS_IF_TEMPLATES = [
    '1.3.6.1.2.1.2.2.1.1', '1.3.6.1.2.1.2.2.1.2', '1.3.6.1.2.1.2.2.1.3',
    '1.3.6.1.2.1.2.2.1.5', '1.3.6.1.2.1.2.2.1.6', '1.3.6.1.2.1.2.2.1.7',
    '1.3.6.1.2.1.2.2.1.8', '1.3.6.1.2.1.2.2.1.10', '1.3.6.1.2.1.2.2.1.16',
]


# ============================================================================
# DÉCHIFFREMENT SNMPv3 (RFC 3414 - USM avec SHA/DES)
# ============================================================================

def _password_to_key_sha(password: str, engine_id: bytes) -> bytes:
    """RFC 3414 A.2 - Dérivation de clé depuis mot de passe + Engine ID."""
    pwd = password.encode('utf-8')
    pwd_len = len(pwd)
    hasher = hashlib.sha1()
    count = 0
    pwd_idx = 0
    while count < 1048576:
        block = bytearray(64)
        for i in range(64):
            block[i] = pwd[pwd_idx % pwd_len]
            pwd_idx += 1
        hasher.update(bytes(block))
        count += 64
    ku = hasher.digest()
    return hashlib.sha1(ku + engine_id + ku).digest()


def _decrypt_des_cbc(encrypted: bytes, priv_password: str,
                     engine_id: bytes, priv_params: bytes) -> Optional[bytes]:
    """Déchiffre un ScopedPDU chiffré en DES-CBC (RFC 3414)."""
    if not CRYPTO_AVAILABLE or len(priv_params) != 8:
        return None
    localized_key = _password_to_key_sha(priv_password, engine_id)
    des_key = localized_key[:8]
    pre_iv = localized_key[8:16]
    iv = bytes(a ^ b for a, b in zip(pre_iv, priv_params))
    try:
        cipher = DES_cipher.new(des_key, DES_cipher.MODE_CBC, iv)
        return cipher.decrypt(encrypted)
    except Exception:
        return None


# ============================================================================
# PARSEUR BER MANUEL (gère tous les tags ASN.1 y compris context-specific)
# ============================================================================

def _ber_read_tlv(data: bytes, offset: int = 0):
    """Lit un TLV BER. Retourne (tag_byte, value_bytes, next_offset) ou None."""
    if offset >= len(data):
        return None
    tag_byte = data[offset]
    offset += 1
    if offset >= len(data):
        return None
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        n_bytes = length_byte & 0x7F
        if n_bytes == 0 or offset + n_bytes > len(data):
            return None
        length = int.from_bytes(data[offset:offset + n_bytes], 'big')
        offset += n_bytes
    else:
        length = length_byte
    if offset + length > len(data):
        length = len(data) - offset
    value = data[offset:offset + length]
    return tag_byte, value, offset + length


def _ber_parse_children(data: bytes) -> list:
    """Parse tous les éléments TLV enfants d'un CONSTRUCTED type."""
    children = []
    offset = 0
    while offset < len(data):
        result = _ber_read_tlv(data, offset)
        if result is None:
            break
        tag_byte, value, next_offset = result
        children.append((tag_byte, value))
        offset = next_offset
    return children


def _ber_to_int(data: bytes) -> int:
    if not data:
        return 0
    return int.from_bytes(data, 'big', signed=True)


def _ber_to_oid(data: bytes) -> str:
    if not data:
        return ''
    oid_parts = [str(data[0] // 40), str(data[0] % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            oid_parts.append(str(value))
            value = 0
    return '.'.join(oid_parts)


def _ber_value_to_str(tag_byte: int, value: bytes) -> str:
    """Convertit une valeur BER en string lisible selon son tag."""
    tag_class = (tag_byte & 0xC0) >> 6
    if tag_class != 0:
        return value.hex()
    tag_num = tag_byte & 0x1F
    if tag_num == 2:  # INTEGER
        return str(_ber_to_int(value))
    elif tag_num == 4:  # OCTET STRING
        try:
            return value.decode('utf-8', errors='replace')
        except Exception:
            return value.hex()
    elif tag_num == 5:  # NULL
        return ''
    elif tag_num == 6:  # OBJECT IDENTIFIER
        return _ber_to_oid(value)
    else:
        if tag_byte in (0x41, 0x42, 0x43, 0x46, 0x47):
            return str(int.from_bytes(value, 'big'))
        if tag_byte == 0x44:
            return value.hex()
        if tag_byte == 0x40:
            if len(value) == 4:
                return '.'.join(str(b) for b in value)
        return value.hex() if value else ''


# ============================================================================
# PARSEUR SNMPv3 BRUT
# ============================================================================

def parse_snmpv3_raw(raw_bytes: bytes, priv_password: str = None) -> Optional[Dict]:
    """Parse un paquet SNMPv3 brut (bytes UDP payload)."""
    try:
        top = _ber_read_tlv(raw_bytes, 0)
        if not top or top[0] != 0x30:
            return None
        children = _ber_parse_children(top[1])
        if len(children) < 4:
            return None

        version = _ber_to_int(children[0][1])
        if version != 3:
            return None

        hdr_children = _ber_parse_children(children[1][1])
        if len(hdr_children) < 4:
            return None

        msg_id = _ber_to_int(hdr_children[0][1])
        msg_flags_raw = hdr_children[2][1]
        auth_flag = bool(msg_flags_raw[0] & 0x01) if msg_flags_raw else False
        priv_flag = bool(msg_flags_raw[0] & 0x02) if msg_flags_raw else False

        if auth_flag and priv_flag:
            sec_level = 'authPriv'
        elif auth_flag:
            sec_level = 'authNoPriv'
        else:
            sec_level = 'noAuthNoPriv'

        usm_raw = children[2][1]
        usm_seq = _ber_read_tlv(usm_raw, 0)
        if not usm_seq:
            return None
        usm_children = _ber_parse_children(usm_seq[1])
        if len(usm_children) < 6:
            return None

        engine_id = usm_children[0][1]
        username = usm_children[3][1].decode('utf-8', errors='replace')
        priv_params = usm_children[5][1]

        pdu_type = 'Encrypted'
        varbinds = []
        request_id = 0
        error_status = '0'
        error_index = 0

        msg_data_tag = children[3][0]
        msg_data_value = children[3][1]

        if priv_flag and msg_data_tag == 0x04:
            if priv_password and engine_id:
                decrypted = _decrypt_des_cbc(
                    msg_data_value, priv_password, engine_id, priv_params
                )
                if decrypted:
                    pdu_type, request_id, error_status, error_index, varbinds = \
                        _parse_scoped_pdu_ber(decrypted)
        elif msg_data_tag == 0x30:
            pdu_type, request_id, error_status, error_index, varbinds = \
                _parse_scoped_pdu_ber(children[3][1], already_unwrapped=True)

        return {
            'msg_id': msg_id,
            'security_level': sec_level,
            'engine_id': engine_id.hex(),
            'username': username,
            'type_pdu': pdu_type,
            'request_id': request_id,
            'error_status': error_status,
            'error_index': error_index,
            'varbinds': varbinds,
        }
    except Exception:
        return None


def _parse_scoped_pdu_ber(raw_bytes: bytes, already_unwrapped: bool = False) -> tuple:
    """Parse un ScopedPDU déchiffré ou en clair avec le parseur BER manuel."""
    pdu_type = 'Unknown'
    request_id = 0
    error_status = '0'
    error_index = 0
    varbinds = []

    try:
        if already_unwrapped:
            scoped_value = raw_bytes
        else:
            scoped_tlv = _ber_read_tlv(raw_bytes, 0)
            if not scoped_tlv or scoped_tlv[0] != 0x30:
                return pdu_type, request_id, error_status, error_index, varbinds
            scoped_value = scoped_tlv[1]

        scoped_children = _ber_parse_children(scoped_value)
        if len(scoped_children) < 3:
            return pdu_type, request_id, error_status, error_index, varbinds

        pdu_tag = scoped_children[2][0]
        pdu_value = scoped_children[2][1]
        tag_id = pdu_tag & 0x1F
        pdu_type = PDU_TYPE_TAGS.get(tag_id, f'UNKNOWN_{tag_id}')

        pdu_children = _ber_parse_children(pdu_value)
        if len(pdu_children) < 4:
            return pdu_type, request_id, error_status, error_index, varbinds

        request_id = _ber_to_int(pdu_children[0][1])
        error_status = str(_ber_to_int(pdu_children[1][1]))
        error_index = _ber_to_int(pdu_children[2][1])

        vb_list_value = pdu_children[3][1]
        vb_items = _ber_parse_children(vb_list_value)
        for vb_tag, vb_value in vb_items:
            vb_children = _ber_parse_children(vb_value)
            if len(vb_children) >= 2:
                oid_str = _ber_to_oid(vb_children[0][1])
                val_str = _ber_value_to_str(vb_children[1][0], vb_children[1][1])
                varbinds.append({'oid': oid_str, 'value': val_str})
    except Exception:
        pass

    return pdu_type, request_id, error_status, error_index, varbinds


def parse_v2c_raw(raw_bytes: bytes) -> Optional[Dict]:
    """Parse un paquet SNMPv2c brut (bytes UDP payload) via BER.
    Structure: SEQUENCE { INTEGER version, OCTET STRING community, PDU }
    """
    try:
        top = _ber_read_tlv(raw_bytes, 0)
        if not top or top[0] != 0x30:
            return None
        children = _ber_parse_children(top[1])
        if len(children) < 3:
            return None

        version = _ber_to_int(children[0][1])
        if version != 1:
            return None

        # Community string
        community = 'public'
        if children[1][0] == 0x04:
            try:
                community = children[1][1].decode('utf-8', errors='replace')
            except Exception:
                community = children[1][1].hex()

        # PDU (context-specific tag: 0xA0=GET, 0xA1=GETNEXT, etc.)
        pdu_tag = children[2][0]
        pdu_value = children[2][1]
        tag_id = pdu_tag & 0x1F
        type_pdu = PDU_TYPE_TAGS.get(tag_id, f'UNKNOWN_{tag_id}')

        # PDU content: [request-id, error-status, error-index, varbind-list]
        pdu_children = _ber_parse_children(pdu_value)
        if len(pdu_children) < 4:
            return {'community': community, 'type_pdu': type_pdu,
                    'request_id': 0, 'error_status': '0', 'error_index': 0,
                    'varbinds': []}

        request_id = _ber_to_int(pdu_children[0][1])
        error_status = str(_ber_to_int(pdu_children[1][1]))
        error_index = _ber_to_int(pdu_children[2][1])

        varbinds = []
        vb_items = _ber_parse_children(pdu_children[3][1])
        for vb_tag, vb_value in vb_items:
            vb_children = _ber_parse_children(vb_value)
            if len(vb_children) >= 2:
                oid_str = _ber_to_oid(vb_children[0][1])
                # NULL (tag 0x05) = question GET (pas de valeur)
                if vb_children[1][0] == 0x05:
                    val_str = 'NULL'
                else:
                    val_str = _ber_value_to_str(
                        vb_children[1][0], vb_children[1][1])
                varbinds.append({'oid': oid_str, 'value': val_str})

        return {
            'community': community,
            'type_pdu': type_pdu,
            'request_id': request_id,
            'error_status': error_status,
            'error_index': error_index,
            'varbinds': varbinds,
        }
    except Exception:
        return None


# ============================================================================
# FILE D'ATTENTE THREAD-SAFE
# ============================================================================

class SNMPPacketQueue:
    def __init__(self, max_size=100000):
        self.queue = queue.Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.packet_count = 0

    def put_packet(self, packet_info: Dict):
        try:
            self.queue.put_nowait(packet_info)
            with self.lock:
                self.packet_count += 1
        except queue.Full:
            logger.warning("[QUEUE] File pleine, paquet ignoré")

    def get_packet(self, timeout=1.0) -> Optional[Dict]:
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def size(self):
        return self.queue.qsize()


# ============================================================================
# COLLECTEUR UNIFIÉ v2c + v3
# ============================================================================

class UnifiedSNMPCollector:
    def __init__(self, api_endpoint: str, api_key: str,
                 interface: str = None,
                 switch_ip: str = None, username: str = None,
                 auth_password: str = None, priv_password: str = None,
                 engine_id_hex: str = None, poll_interval: int = 60,
                 num_workers: int = 3, verbose: bool = True,
                 listen_port: int = 162):

        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.interface = interface
        self.num_workers = num_workers
        self.verbose = verbose
        self.listen_port = listen_port

        # v3 config (optionnel)
        self.switch_ip = switch_ip
        self.username = username
        self.auth_password = auth_password
        self.priv_password = priv_password
        self.engine_id_hex = engine_id_hex
        self.poll_interval = poll_interval

        # Mode v3 activé si tous les credentials sont fournis
        self.v3_enabled = all([switch_ip, username, auth_password, priv_password])
        self.v3_decrypt = bool(priv_password) and CRYPTO_AVAILABLE

        self.packet_queue = SNMPPacketQueue(max_size=100000)
        self.running = True
        self.worker_threads = []

        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        })
        self.session.verify = False

        self.stats = {
            'v2c_captured': 0,
            'v3_sniffed': 0,
            'v3_decrypted': 0,
            'v3_polls': 0,
            'total_processed': 0,
            'api_sent': 0,
            'api_failed': 0,
            'alerts': 0,
        }
        self.stats_lock = threading.Lock()

        logger.info("=" * 60)
        logger.info("[INIT] Collecteur SNMP Unifié v1.0 (v2c + v3)")
        logger.info(f"[INIT] API: {api_endpoint}")
        logger.info(f"[INIT] Interface: {interface or 'auto'}")
        logger.info(f"[INIT] Scapy: {'OUI' if SCAPY_AVAILABLE else 'NON'}")
        if self.v3_enabled:
            logger.info(f"[INIT] Mode v3: OUI (switch: {switch_ip})")
            logger.info(f"[INIT] Utilisateur SNMPv3: {username} (SHA/DES)")
            logger.info(f"[INIT] Déchiffrement DES: "
                         f"{'OUI' if self.v3_decrypt else 'NON'}")
            logger.info(f"[INIT] Polling actif: "
                         f"{'OUI' if HLAPI_AVAILABLE else 'NON'}")
        else:
            logger.info("[INIT] Mode v3: NON (capture passive v2c uniquement)")
        logger.info("=" * 60)

    # ----------------------------------------------------------------
    # RÉSOLUTION OID
    # ----------------------------------------------------------------

    def get_oid_info(self, oid: str) -> tuple:
        if oid in OID_LIBRARY:
            return OID_LIBRARY[oid]
        best_match = None
        max_len = 0
        for k, v in OID_LIBRARY.items():
            if oid.startswith(k) and len(k) > max_len:
                if len(oid) == len(k) or oid[len(k)] == '.':
                    best_match = v
                    max_len = len(k)
        return best_match if best_match else ("Unknown_OID", "OID non reconnu")

    # ----------------------------------------------------------------
    # ANALYSE DE SÉVÉRITÉ
    # ----------------------------------------------------------------

    def analyser_severite(self, packet_info: Dict) -> str:
        contenu = packet_info.get('contenu', {})
        varbinds = contenu.get('varbinds', [])
        type_pdu = packet_info.get('type_pdu', '')
        is_trap = type_pdu == 'Trap'
        score = 0

        if type_pdu == 'SetRequest':
            score += 25
        if is_trap:
            trap_type = contenu.get('trap_type', '')
            if trap_type == 'AUTH_FAILURE':
                score += 40
            if trap_type == 'LINK_DOWN':
                score += 15

        for vb in varbinds:
            oid = vb.get('oid', '')
            nom = vb.get('oid_name', '')
            if len(oid) > 128:
                score += 50
            if oid and not oid.startswith('1.3.'):
                score += 20
            if oid and not re.match(r'^[0-9.]+$', oid):
                score += 30
            if is_trap and 'ifAdminStatus' in nom:
                score += 60
            if is_trap and 'sysName' in nom:
                score += 30
            if type_pdu == 'SetRequest':
                if 'sysLocation' in nom:
                    score += 40
                if 'ifAdminStatus' in nom:
                    score += 60
                if 'sysName' in nom:
                    score += 30

        if score >= 50:
            return 'CRITIQUE'
        elif score >= 20:
            return 'ELEVEE'
        elif score > 0:
            return 'SUSPECT'
        return 'NORMAL'

    # ----------------------------------------------------------------
    # PARSING V2C (via parseur BER, indépendant de Scapy SNMP layer)
    # ----------------------------------------------------------------

    def _parse_v2c_packet(self, raw_data, src_ip, src_port, dst_ip, dst_port):
        """Parse un paquet SNMPv2c depuis les bytes bruts via BER."""
        parsed = parse_v2c_raw(raw_data)
        if not parsed:
            return None

        varbinds_list = []
        valeurs_dict = {}
        oid_racine = "Non détecté"

        for vb in parsed.get('varbinds', []):
            oid_str = vb.get('oid', '')
            val_str = vb.get('value', '')
            nom_oid, desc_oid = self.get_oid_info(oid_str)
            valeurs_dict[oid_str] = val_str
            varbinds_list.append({
                "oid": oid_str, "oid_name": nom_oid,
                "oid_desc": desc_oid, "value": val_str,
                "type": "ber_parsed"
            })
            if oid_racine == "Non détecté":
                oid_racine = oid_str

        return {
            '_version': 2,
            'source_ip': src_ip, 'source_port': src_port,
            'dest_ip': dst_ip, 'dest_port': dst_port,
            'community': parsed.get('community', 'public'),
            'oid_racine': oid_racine,
            'type_pdu': parsed.get('type_pdu', 'Unknown'),
            'request_id': parsed.get('request_id', 0),
            'error_status': parsed.get('error_status', '0'),
            'error_index': parsed.get('error_index', 0),
            'contenu': {
                'varbinds': varbinds_list,
                'dico_valeurs': valeurs_dict,
                'capture_mode': 'passive',
            }
        }

    # ----------------------------------------------------------------
    # PARSING V3 (BER parser + déchiffrement DES)
    # ----------------------------------------------------------------

    def _parse_v3_packet(self, raw_data, src_ip, src_port, dst_ip, dst_port):
        """Parse un paquet SNMPv3 brut. Retourne (packet_info, is_decrypted)."""
        priv_pw = self.priv_password if self.v3_decrypt else None
        parsed = parse_snmpv3_raw(raw_data, priv_pw)
        if not parsed:
            return None

        pdu_type = parsed['type_pdu']
        is_decrypted = pdu_type != 'Encrypted'

        varbinds_enriched = []
        valeurs_dict = {}
        oid_racine = "Non détecté"

        for vb in parsed.get('varbinds', []):
            oid_str = vb.get('oid', '')
            val_str = vb.get('value', '')
            nom_oid, desc_oid = self.get_oid_info(oid_str)
            varbinds_enriched.append({
                "oid": oid_str, "oid_name": nom_oid,
                "oid_desc": desc_oid, "value": val_str,
                "type": "snmpv3_captured"
            })
            valeurs_dict[oid_str] = val_str
            if oid_racine == "Non détecté":
                oid_racine = oid_str

        packet_info = {
            '_version': 3,
            'source_ip': src_ip, 'source_port': src_port,
            'dest_ip': dst_ip, 'dest_port': dst_port,
            'oid_racine': oid_racine,
            'type_pdu': pdu_type,
            'request_id': parsed.get('request_id', 0),
            'error_status': parsed.get('error_status', '0'),
            'error_index': parsed.get('error_index', 0),
            'contexte': '',
            'niveau_securite': parsed.get('security_level', 'authPriv'),
            'utilisateur': parsed.get('username', ''),
            'engine_id': parsed.get('engine_id', ''),
            'msg_id': parsed.get('msg_id', 0),
            'contenu': {
                'varbinds': varbinds_enriched,
                'dico_valeurs': valeurs_dict,
                'capture_mode': 'passive',
                'decrypted': is_decrypted,
            }
        }

        if pdu_type == 'Trap':
            for vb in varbinds_enriched:
                if vb['oid'] == '1.3.6.1.6.3.1.1.4.1.0':
                    trap_oid = vb['value']
                    packet_info['contenu']['trap_type'] = \
                        TRAP_TYPE_MAPPING.get(trap_oid, 'Trap')
                    packet_info['contenu']['trap_oid'] = trap_oid
                    packet_info['oid_racine'] = trap_oid

        return packet_info, is_decrypted

    # ----------------------------------------------------------------
    # CAPTURE PASSIVE SCAPY (thread)
    # ----------------------------------------------------------------

    def sniffer_thread(self):
        """Capture passive de paquets SNMP via Scapy en mode promiscuous."""
        if not SCAPY_AVAILABLE:
            logger.error("[SNIFFER] Scapy non disponible")
            return

        logger.info("[SNIFFER] Démarrage capture passive (v2c + v3)...")
        logger.info("[SNIFFER] Filtre: UDP port 161 ou 162")
        if self.interface:
            logger.info(f"[SNIFFER] Interface: {self.interface}")

        def packet_callback(pkt):
            if not self.running:
                return
            try:
                if not (IP in pkt and UDP in pkt):
                    return

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

                if src_port not in (161, 162) and dst_port not in (161, 162):
                    return

                # Extraire payload UDP brut (méthode fiable)
                # On reconstruit les bytes depuis le layer UDP,
                # en évitant pkt[Raw] qui peut pointer vers du padding
                udp_payload = pkt[UDP].payload
                raw_data = bytes(udp_payload)

                # Scapy peut ajouter du padding : on tronque à la
                # taille réelle via le champ UDP length
                udp_len = pkt[UDP].len
                if udp_len and udp_len > 8:
                    raw_data = raw_data[:udp_len - 8]

                if len(raw_data) < 10 or raw_data[0] != 0x30:
                    return

                # Détecter la version SNMP depuis le BER
                top = _ber_read_tlv(raw_data, 0)
                if not top:
                    return
                children = _ber_parse_children(top[1])
                if not children:
                    return
                version = _ber_to_int(children[0][1])

                packet_info = None

                if version == 1:
                    # ---- SNMPv2c (parseur BER) ----
                    packet_info = self._parse_v2c_packet(
                        raw_data, src_ip, src_port, dst_ip, dst_port)
                    if packet_info:
                        with self.stats_lock:
                            self.stats['v2c_captured'] += 1

                elif version == 3:
                    # ---- SNMPv3 ----
                    result = self._parse_v3_packet(
                        raw_data, src_ip, src_port, dst_ip, dst_port
                    )
                    if result:
                        packet_info, is_decrypted = result
                        with self.stats_lock:
                            self.stats['v3_sniffed'] += 1
                            if is_decrypted:
                                self.stats['v3_decrypted'] += 1

                if not packet_info:
                    return

                # Analyse de sévérité
                severite = self.analyser_severite(packet_info)

                if severite in ['SUSPECT', 'ELEVEE', 'CRITIQUE']:
                    packet_info['contenu']['alerte_securite'] = {
                        'niveau': severite,
                        'message': f"{packet_info['type_pdu']} suspect "
                                   f"{src_ip}->{dst_ip}",
                        'timestamp': datetime.datetime.now().isoformat(),
                        'details': f"PDU: {packet_info['type_pdu']}",
                        'action_requise': f"Vérifier {src_ip}"
                    }
                    with self.stats_lock:
                        self.stats['alerts'] += 1

                self.packet_queue.put_packet(packet_info)

                if self.verbose:
                    v_tag = "v2c" if packet_info['_version'] == 2 else "v3"
                    pdu_type = packet_info['type_pdu']
                    vb_count = len(
                        packet_info['contenu'].get('varbinds', []))
                    logger.info(
                        f"[SNIFFER] [{v_tag}] {src_ip}:{src_port} -> "
                        f"{dst_ip}:{dst_port} | "
                        f"{pdu_type} | {vb_count} OIDs | Sev: {severite}"
                    )

            except Exception as e:
                logger.debug(f"[SNIFFER] Erreur parsing: {e}")

        try:
            scapy_sniff(
                filter="udp port 161 or udp port 162",
                prn=packet_callback,
                store=0,
                iface=self.interface,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            logger.error(
                "[SNIFFER] Permission refusée. Lancez en administrateur.")
        except Exception as e:
            logger.error(f"[SNIFFER] Erreur Scapy: {e}")

    # ----------------------------------------------------------------
    # ENVOI VERS L'API
    # ----------------------------------------------------------------

    def send_to_api(self, packets: List[Dict]) -> bool:
        if not packets:
            return True

        success_count = 0

        for packet in packets:
            try:
                version = packet.pop('_version', 2)

                if version == 2:
                    url = f"{self.api_endpoint}/snmp/v2c/add"
                    payload = {
                        'source_ip': packet.get('source_ip'),
                        'source_port': packet.get('source_port'),
                        'dest_ip': packet.get('dest_ip'),
                        'dest_port': packet.get('dest_port'),
                        'community': packet.get('community', 'public'),
                        'oid_racine': packet.get('oid_racine'),
                        'type_pdu': packet.get('type_pdu'),
                        'request_id': packet.get('request_id', 0),
                        'error_status': packet.get('error_status', '0'),
                        'error_index': packet.get('error_index', 0),
                        'contenu': packet.get('contenu'),
                    }
                else:
                    url = f"{self.api_endpoint}/snmp/v3/add"
                    payload = {
                        'source_ip': packet.get('source_ip'),
                        'source_port': packet.get('source_port'),
                        'dest_ip': packet.get('dest_ip'),
                        'dest_port': packet.get('dest_port'),
                        'oid_racine': packet.get('oid_racine'),
                        'type_pdu': packet.get('type_pdu'),
                        'contexte': packet.get('contexte', ''),
                        'niveau_securite': packet.get(
                            'niveau_securite', 'authPriv'),
                        'utilisateur': packet.get('utilisateur'),
                        'request_id': packet.get('request_id', 0),
                        'error_status': packet.get('error_status', '0'),
                        'error_index': packet.get('error_index', 0),
                        'engine_id': packet.get('engine_id'),
                        'msg_id': packet.get('msg_id'),
                        'contenu': packet.get('contenu'),
                    }

                if payload.get('type_pdu') == 'Unknown':
                    continue

                response = self.session.post(url, json=payload, timeout=5)

                if response.status_code in [200, 201]:
                    success_count += 1
                else:
                    logger.warning(
                        f"[API] Rejet {response.status_code}: "
                        f"{response.text[:200]}"
                    )

            except requests.exceptions.ConnectionError:
                logger.error(
                    f"[API] Connexion impossible vers {self.api_endpoint}")
            except Exception as e:
                logger.error(f"[API] Erreur d'envoi: {e}")

        with self.stats_lock:
            self.stats['api_sent'] += success_count
            self.stats['api_failed'] += (len(packets) - success_count)

        return success_count > 0

    # ----------------------------------------------------------------
    # WORKERS D'ENVOI (avec batching)
    # ----------------------------------------------------------------

    def worker_thread(self, worker_id: int):
        logger.info(f"[WORKER-{worker_id}] Démarré")
        batch = []
        last_send = time.time()

        while self.running:
            try:
                packet = self.packet_queue.get_packet(timeout=0.1)
                if packet:
                    batch.append(packet)
                    with self.stats_lock:
                        self.stats['total_processed'] += 1

                if len(batch) >= 20 or (batch and time.time() - last_send > 1.0):
                    self.send_to_api(batch)
                    batch = []
                    last_send = time.time()
            except Exception as e:
                logger.error(f"[WORKER-{worker_id}] Erreur: {e}")

    # ----------------------------------------------------------------
    # POLLING ACTIF v3 (async) - optionnel
    # ----------------------------------------------------------------

    async def _snmp_get_batch(self, hlapi_engine, user_data, target,
                              oid_list: List[str]) -> List[tuple]:
        results = []
        for i in range(0, len(oid_list), 10):
            batch_oids = oid_list[i:i+10]
            object_types = [
                HlapiObjectType(HlapiObjectIdentity(oid))
                for oid in batch_oids
            ]
            try:
                errorIndication, errorStatus, errorIndex, varBinds = \
                    await hlapi_get_cmd(
                        hlapi_engine, user_data, target,
                        HlapiContextData(), *object_types
                    )
                if errorIndication or errorStatus:
                    continue
                for oid, val in varBinds:
                    oid_str = oid.prettyPrint()
                    val_str = val.prettyPrint()
                    if 'noSuch' in val_str or 'No Such' in val_str:
                        continue
                    results.append((oid_str, val_str, val.__class__.__name__))
            except Exception:
                continue
        return results

    async def poll_switch(self):
        """Polling actif du switch par GET SNMPv3."""
        if not HLAPI_AVAILABLE or not self.v3_enabled:
            return

        logger.info(f"[POLL] Polling actif v3 vers {self.switch_ip} "
                     f"(intervalle: {self.poll_interval}s)")

        per_port_oids = {}
        for idx in POLL_IF_INDICES:
            per_port_oids[idx] = [
                f"{tpl}.{idx}" for tpl in POLL_OIDS_IF_TEMPLATES
            ]

        poll_count = 0

        while self.running:
            poll_count += 1
            try:
                hlapi_engine = HlapiEngine()
                user_data = HlapiUsmUserData(
                    self.username, self.auth_password, self.priv_password,
                    authProtocol=AUTH_SHA, privProtocol=PRIV_DES
                )
                try:
                    target = await HlapiTarget.create(
                        (self.switch_ip, 161), timeout=5, retries=2
                    )
                except (TypeError, AttributeError):
                    target = HlapiTarget(
                        (self.switch_ip, 161), timeout=5, retries=2
                    )

                engine_id_hex = self.engine_id_hex or ""

                # Système
                sys_results = await self._snmp_get_batch(
                    hlapi_engine, user_data, target, POLL_OIDS_SYSTEM
                )
                if sys_results:
                    vb_list = []
                    vd = {}
                    for oid_str, val_str, tn in sys_results:
                        nom, desc = self.get_oid_info(oid_str)
                        vb_list.append({"oid": oid_str, "oid_name": nom,
                                        "oid_desc": desc, "value": val_str,
                                        "type": tn})
                        vd[oid_str] = val_str
                    self.packet_queue.put_packet({
                        '_version': 3,
                        'source_ip': self.switch_ip, 'source_port': 161,
                        'dest_ip': '10.204.0.135',
                        'dest_port': self.listen_port,
                        'oid_racine': '1.3.6.1.2.1.1',
                        'type_pdu': 'Response',
                        'request_id': poll_count,
                        'error_status': '0', 'error_index': 0,
                        'contexte': '', 'niveau_securite': 'authPriv',
                        'utilisateur': self.username,
                        'engine_id': engine_id_hex,
                        'msg_id': poll_count,
                        'contenu': {'varbinds': vb_list, 'dico_valeurs': vd,
                                    'capture_mode': 'active'}
                    })
                    with self.stats_lock:
                        self.stats['v3_polls'] += 1

                # Interfaces
                for idx, oid_list in per_port_oids.items():
                    port_results = await self._snmp_get_batch(
                        hlapi_engine, user_data, target, oid_list
                    )
                    if not port_results:
                        continue
                    vb_list = []
                    vd = {}
                    for oid_str, val_str, tn in port_results:
                        nom, desc = self.get_oid_info(oid_str)
                        vb_list.append({"oid": oid_str, "oid_name": nom,
                                        "oid_desc": desc, "value": val_str,
                                        "type": tn})
                        vd[oid_str] = val_str
                    self.packet_queue.put_packet({
                        '_version': 3,
                        'source_ip': self.switch_ip, 'source_port': 161,
                        'dest_ip': '10.204.0.135',
                        'dest_port': self.listen_port,
                        'oid_racine': f'1.3.6.1.2.1.2.2.1.1.{idx}',
                        'type_pdu': 'Response',
                        'request_id': poll_count,
                        'error_status': '0', 'error_index': 0,
                        'contexte': '', 'niveau_securite': 'authPriv',
                        'utilisateur': self.username,
                        'engine_id': engine_id_hex,
                        'msg_id': poll_count,
                        'contenu': {'varbinds': vb_list, 'dico_valeurs': vd,
                                    'capture_mode': 'active'}
                    })
                    with self.stats_lock:
                        self.stats['v3_polls'] += 1

            except Exception as e:
                logger.warning(f"[POLL] Erreur: {e}")
                await asyncio.sleep(2)
                continue

            await asyncio.sleep(self.poll_interval)

    # ----------------------------------------------------------------
    # AFFICHAGE STATS
    # ----------------------------------------------------------------

    def stats_printer(self):
        while self.running:
            time.sleep(10)
            with self.stats_lock:
                s = self.stats
                logger.info(
                    f"[STATS] v2c:{s['v2c_captured']} | "
                    f"v3:{s['v3_sniffed']} "
                    f"(déchiffrés:{s['v3_decrypted']}) | "
                    f"Polls:{s['v3_polls']} | "
                    f"Q:{self.packet_queue.size()} | "
                    f"API OK:{s['api_sent']} | "
                    f"API Fail:{s['api_failed']} | "
                    f"Alertes:{s['alerts']}"
                )

    # ----------------------------------------------------------------
    # DÉMARRAGE PRINCIPAL (async)
    # ----------------------------------------------------------------

    async def start(self):
        # Workers API
        for i in range(self.num_workers):
            t = threading.Thread(
                target=self.worker_thread, args=(i,), daemon=True
            )
            t.start()
            self.worker_threads.append(t)

        # Stats
        stats_thread = threading.Thread(
            target=self.stats_printer, daemon=True
        )
        stats_thread.start()

        # Sniffer passif Scapy (thread)
        if SCAPY_AVAILABLE:
            sniffer_t = threading.Thread(
                target=self.sniffer_thread, daemon=True
            )
            sniffer_t.start()
            logger.info("[START] Sniffer passif Scapy lancé (v2c + v3)")
        else:
            logger.warning("[START] Scapy non disponible")

        # Polling actif v3 (async task) - seulement si v3 activé
        poll_task = None
        if self.v3_enabled and HLAPI_AVAILABLE:
            poll_task = asyncio.create_task(self.poll_switch())
            logger.info("[START] Polling actif v3 lancé")

        logger.info("=" * 60)
        logger.info("[START] COLLECTEUR SNMP UNIFIÉ OPÉRATIONNEL")
        logger.info(f"[START] Capture passive v2c+v3: "
                     f"{'OUI' if SCAPY_AVAILABLE else 'NON'}")
        logger.info(f"[START] Polling actif v3: "
                     f"{'OUI' if (self.v3_enabled and HLAPI_AVAILABLE) else 'NON'}")
        logger.info("[START] Ctrl+C pour arrêter")
        logger.info("=" * 60)

        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False
            if poll_task and not poll_task.done():
                poll_task.cancel()
                try:
                    await poll_task
                except asyncio.CancelledError:
                    pass
            self.print_final_stats()

    def print_final_stats(self):
        with self.stats_lock:
            s = self.stats
        logger.info("=" * 60)
        logger.info("STATISTIQUES FINALES")
        logger.info(f"  Paquets v2c capturés  : {s['v2c_captured']}")
        logger.info(f"  Paquets v3 sniffés    : {s['v3_sniffed']}")
        logger.info(f"  Paquets v3 déchiffrés : {s['v3_decrypted']}")
        logger.info(f"  Polls actifs v3       : {s['v3_polls']}")
        logger.info(f"  Total traités         : {s['total_processed']}")
        logger.info(f"  Envoyés à l'API       : {s['api_sent']}")
        logger.info(f"  Échecs API            : {s['api_failed']}")
        logger.info(f"  Alertes sécurité      : {s['alerts']}")
        logger.info("=" * 60)


# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Collecteur SNMP Unifié v2c + v3 (passif + actif)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes de capture:
  PASSIF: Scapy sniffe tout le trafic SNMP v2c et v3 (nécessite SPAN)
  ACTIF:  Polling GET v3 continu (optionnel, nécessite --switch + credentials)

Exemples:
  # Capture passive v2c uniquement
  python %(prog)s -a https://API:8000 -k CLE -i "Ethernet 2"

  # Capture passive v2c+v3 + polling actif v3
  python %(prog)s -a https://API:8000 -k CLE -i "Ethernet 2" \\
      -s 10.204.0.119 -u Alleria_W --auth-password Vereesa_W \\
      --priv-password Windrunner -e 80004fb8054d534917e0c200
        """
    )

    # Requis
    parser.add_argument('-a', '--api', required=True,
                        help="URL de l'API (ex: https://10.204.0.158:8000)")
    parser.add_argument('-k', '--key', required=True,
                        help="Clé API pour l'authentification")

    # Optionnel (général)
    parser.add_argument('-i', '--interface', default=None,
                        help='Interface réseau pour Scapy (ex: "Ethernet 2")')
    parser.add_argument('-w', '--workers', type=int, default=3,
                        help='Nombre de threads workers (défaut: 3)')
    parser.add_argument('-p', '--port', type=int, default=162,
                        help="Port d'écoute (défaut: 162)")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Mode silencieux')

    # Optionnel (v3)
    v3_group = parser.add_argument_group(
        'SNMPv3 (optionnel)',
        'Paramètres pour le polling actif et le déchiffrement v3')
    v3_group.add_argument('-s', '--switch', default=None,
                          help='Adresse IP du switch (active le polling v3)')
    v3_group.add_argument('-u', '--username', default=None,
                          help="Nom d'utilisateur SNMPv3")
    v3_group.add_argument('--auth-password', default=None,
                          help="Mot de passe d'authentification (SHA)")
    v3_group.add_argument('--priv-password', default=None,
                          help='Mot de passe de chiffrement (DES)')
    v3_group.add_argument('-e', '--engine-id', default=None,
                          help='Engine ID du switch en hexadécimal')
    v3_group.add_argument('--poll-interval', type=int, default=60,
                          help='Intervalle entre polls actifs (défaut: 60s)')

    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Vérifier cohérence des paramètres v3
    v3_args = [args.switch, args.username, args.auth_password, args.priv_password]
    if any(v3_args) and not all(v3_args):
        parser.error(
            "Pour activer le mode v3, tous les paramètres sont requis: "
            "--switch, --username, --auth-password, --priv-password")

    collector = UnifiedSNMPCollector(
        api_endpoint=args.api,
        api_key=args.key,
        interface=args.interface,
        switch_ip=args.switch,
        username=args.username,
        auth_password=args.auth_password,
        priv_password=args.priv_password,
        engine_id_hex=args.engine_id,
        poll_interval=args.poll_interval,
        num_workers=args.workers,
        verbose=not args.quiet,
        listen_port=args.port,
    )

    try:
        asyncio.run(collector.start())
    except KeyboardInterrupt:
        collector.running = False
        logger.info("[MAIN] Arrêt par Ctrl+C")


if __name__ == '__main__':
    main()
