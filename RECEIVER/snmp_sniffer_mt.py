#!/usr/bin/env python3
"""
SNMP Packet Sniffer v4.4 - V2C FULL CAPTURE
Auteur: Étudiant 1 - Réseaux & Télécoms RT3
Projet: SAE 501-502 - Supervision Réseau
Description: Capture TOUT le trafic SNMP (Questions + Réponses) pour archivage complet.
"""

from scapy.all import *
from scapy.layers.snmp import SNMP
import scapy.config
import json
import datetime
import sys
import argparse
import threading
import queue
import requests
import logging
from collections import defaultdict
from typing import Dict, List, Optional
import time
import re

# --- CONFIGURATION ---
conf.sniff_promisc = True 

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Mapping PDU pour normalisation
PDU_MAPPING = {
    'GetRequest': 'GET',
    'SNMPget': 'GET',
    'GetNextRequest': 'GETNEXT',
    'SNMPnext': 'GETNEXT',
    'SetRequest': 'SET',
    'SNMPset': 'SET',
    'GetResponse': 'RESPONSE',
    'SNMPresponse': 'RESPONSE',
    'SNMPtrapv2': 'TRAP',
    'SNMPv2_Trap': 'TRAP',
    'Trap': 'TRAP',
    'GetBulkRequest': 'BULK',
    'SNMPbulk': 'BULK',
    'InformRequest': 'INFORM'
}

class SNMPPacketQueue:
    def __init__(self, max_size=100000):
        self.queue = queue.Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.packet_count = 0
        self.stats = defaultdict(int)
    
    def put_packet(self, packet_info: Dict):
        try:
            self.queue.put_nowait(packet_info)
            with self.lock:
                self.packet_count += 1
        except queue.Full:
            pass
    
    def get_packet(self, timeout=1.0) -> Optional[Dict]:
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def size(self):
        return self.queue.qsize()
    
    def get_stats(self):
        with self.lock:
            return {
                'total_queued': self.packet_count,
                'current_size': self.queue.qsize(),
                'stats': dict(self.stats)
            }

class SNMPSnifferMultithreading:
    def __init__(self, interface: str, filter_expr: str, 
                 api_endpoint: str, api_key: str,
                 num_workers: int = 3, verbose: bool = True):
        
        self.interface = interface
        self.filter_expr = filter_expr
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.num_workers = num_workers
        self.verbose = verbose
        
        self.packet_queue = SNMPPacketQueue(max_size=100000)
        self.running = True
        self.capture_thread = None
        self.worker_threads = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        })
        
        self.stats = {
            'total_captured': 0, 'total_processed': 0,
            'api_sent': 0, 'api_failed': 0, 
            'spam_blocked': 0
        }
        self.stats_lock = threading.Lock()
        
        logger.info(f"[INIT] Interface: {self.interface} (Promiscuous: ON)")
        logger.info(f"[INIT] Mode: FULL CAPTURE (GET + RESPONSE)")

    def _safe_val(self, obj):
        try:
            return obj.val if hasattr(obj, 'val') else obj
        except:
            return obj

    def analyser_severite(self, packet_info: Dict) -> str:
        contenu = packet_info.get('contenu', {})
        varbinds = contenu.get('varbinds', [])
        if not varbinds: return 'NORMAL'

        score_anomalie = 0
        for vb in varbinds:
            oid = vb.get('oid', '')
            # OID trop long
            if len(oid) > 128: score_anomalie += 50
            # OID ne respectant pas le standard (sauf s'il est vide/racine)
            if oid and not oid.startswith('1.3.'): score_anomalie += 20
            # Caractères bizarres
            if not re.match(r'^[0-9.]+$', oid): score_anomalie += 30

        if score_anomalie >= 50: return 'CRITIQUE'
        elif score_anomalie >= 20: return 'ELEVEE'
        elif score_anomalie > 0: return 'SUSPECT'
        return 'NORMAL'

    def parse_snmp_packet(self, packet) -> Dict:
        packet_info = {}
        try:
            packet_info['source_ip'] = packet[IP].src if IP in packet else "0.0.0.0"
            packet_info['source_port'] = packet[UDP].sport if UDP in packet else 161
            packet_info['dest_ip'] = packet[IP].dst if IP in packet else "0.0.0.0"
            packet_info['dest_port'] = packet[UDP].dport if UDP in packet else 162
            packet_info['community'] = "public"
            packet_info['oid_racine'] = "Non détecté"
            packet_info['type_pdu'] = "UNKNOWN"
            packet_info['request_id'] = 0
            packet_info['error_status'] = "0"
            packet_info['error_index'] = 0
            packet_info['contenu'] = {"varbinds": [], "dico_valeurs": {}}
            
            if packet.haslayer(SNMP):
                snmp_layer = packet[SNMP]
                
                # Validation Version V2C
                version = self._safe_val(snmp_layer.version)
                if int(version) != 1: return None 

                # Community
                if hasattr(snmp_layer, "community"):
                    val = self._safe_val(snmp_layer.community)
                    packet_info['community'] = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)

                # PDU Parsing
                if hasattr(snmp_layer, "PDU"):
                    pdu = snmp_layer.PDU
                    raw_name = pdu.name
                    clean_name = raw_name.replace('-PDU', '')
                    packet_info['type_pdu'] = PDU_MAPPING.get(clean_name, PDU_MAPPING.get(raw_name, "UNKNOWN"))
                    
                    if hasattr(pdu, "id"):
                        packet_info['request_id'] = int(self._safe_val(pdu.id))
                    
                    if hasattr(pdu, "error_status"):
                        val = self._safe_val(pdu.error_status)
                        packet_info['error_status'] = str(val) if val is not None else "0"
                    
                    if hasattr(pdu, "error_index"):
                        val = self._safe_val(pdu.error_index)
                        packet_info['error_index'] = int(val) if val is not None else 0

                    # VarBinds Parsing
                    varbinds_list = []
                    valeurs_dict = {}
                    oid_racine_trouve = False

                    if hasattr(pdu, "varbindlist"):
                        for varbind in pdu.varbindlist:
                            oid = str(self._safe_val(varbind.oid))
                            val = self._safe_val(varbind.value)
                            type_asn1 = varbind.value.__class__.__name__
                            
                            # Gestion spécifique des NULL (Questions)
                            if type_asn1 == 'ASN1_NULL' or type_asn1 == 'Null':
                                value_str = "NULL" # On marque explicitement NULL au lieu de 0
                            else:
                                try:
                                    value_str = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                                except:
                                    value_str = str(val)

                            # On ajoute tout au dictionnaire, même les NULL (car demandé)
                            valeurs_dict[oid] = value_str

                            varbinds_list.append({
                                "oid": oid,
                                "value": value_str,
                                "type": type_asn1
                            })

                            if not oid_racine_trouve:
                                packet_info['oid_racine'] = oid
                                oid_racine_trouve = True

                    packet_info['contenu'] = {
                        "varbinds": varbinds_list,
                        "dico_valeurs": valeurs_dict
                    }
            else:
                return None

        except Exception as e:
            logger.error(f"[PARSE] Erreur: {e}")
            if Raw in packet: packet_info['contenu'] = {'raw_hex': packet[Raw].load.hex()}

        return packet_info
    
    def packet_callback(self, packet):
        packet_info = self.parse_snmp_packet(packet)
        
        if packet_info: 
            # 1. Vérification Anti-Spam
            severite = self.analyser_severite(packet_info)
            if severite in ['ELEVEE', 'CRITIQUE']:
                packet_info['type_pdu'] = "BLOCKED_SPAM"
                packet_info['contenu']['alerte_securite'] = {
                    "niveau": severite,
                    "message": "OID Suspect détecté",
                    "timestamp": datetime.datetime.now().isoformat()
                }
                with self.stats_lock: self.stats['spam_blocked'] += 1
                # On envoie quand même à la file pour l'alerte API
                self.packet_queue.put_packet(packet_info)
                return

            # 2. Pas de filtrage fonctionnel : ON PREND TOUT (GET & RESPONSE)
            self.packet_queue.put_packet(packet_info)
            with self.stats_lock: self.stats['total_captured'] += 1

    def send_to_api(self, packets: List[Dict]) -> bool:
        if not packets: return True
        
        url = f"{self.api_endpoint}/snmp/v2c/add"
        success_count = 0
        
        for packet in packets:
            try:
                if packet.get('type_pdu') == "UNKNOWN": continue

                payload = {
                    'source_ip': packet.get('source_ip'),
                    'source_port': packet.get('source_port'),
                    'dest_ip': packet.get('dest_ip'),
                    'dest_port': packet.get('dest_port'),
                    'community': packet.get('community'),
                    'oid_racine': packet.get('oid_racine'),
                    'type_pdu': packet.get('type_pdu'),
                    'request_id': packet.get('request_id'),
                    'error_status': packet.get('error_status', "0"),
                    'error_index': packet.get('error_index', 0),
                    'contenu': packet.get('contenu')
                }
                
                response = self.session.post(url, json=payload, timeout=2)
                
                if response.status_code in [200, 201]:
                    success_count += 1
                else:
                    logger.warning(f"[API] Rejet {response.status_code}")
            
            except Exception as e:
                logger.error(f"[API] Erreur d'envoi: {e}")

        with self.stats_lock:
            self.stats['api_sent'] += success_count
            self.stats['api_failed'] += (len(packets) - success_count)
            
        return success_count > 0

    def worker_thread(self, worker_id: int):
        logger.info(f"[WORKER-{worker_id}] Démarré")
        batch = []
        last_send = time.time()
        
        while self.running:
            try:
                packet = self.packet_queue.get_packet(timeout=0.1)
                
                if packet:
                    batch.append(packet)
                    with self.stats_lock: self.stats['total_processed'] += 1
                
                if len(batch) >= 20 or (batch and time.time() - last_send > 1.0):
                    self.send_to_api(batch)
                    batch = []
                    last_send = time.time()
            except Exception as e:
                logger.error(f"[WORKER-{worker_id}] Erreur: {e}")

    def start(self, packet_count=0, timeout=None):
        logger.info(f"[MAIN] Démarrage du sniffer...")
        self.capture_thread = threading.Thread(
            target=lambda: sniff(iface=self.interface, filter=self.filter_expr, 
                               prn=self.packet_callback, count=packet_count, 
                               timeout=timeout, store=False)
        )
        self.capture_thread.start()
        
        for i in range(self.num_workers):
            t = threading.Thread(target=self.worker_thread, args=(i,))
            t.start()
            self.worker_threads.append(t)
        
        try:
            while self.running:
                time.sleep(5)
                self.print_stats()
                if not self.capture_thread.is_alive(): break
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("[MAIN] Arrêt...")
        self.running = False

    def print_stats(self):
        with self.stats_lock:
            s = self.stats
            logger.info(f"[STATS] Q:{self.packet_queue.size()} | Sent:{s['api_sent']} | SpamBlocked:{s['spam_blocked']}")

def get_best_interface():
    try:
        from scapy.arch import get_windows_if_list
        interfaces = get_windows_if_list()
        print("\n--- Interfaces ---")
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface['name']} - {iface['description']}")
            if 'Ethernet' in iface['description'] or 'Intel' in iface['description'] or 'Realtek' in iface['description']:
                return iface['name']
        return conf.iface
    except:
        return 'eth0'

def main():
    parser = argparse.ArgumentParser(description='SNMP Sniffer V4.4 Full Capture')
    parser.add_argument('-i', '--interface', default=None, help='Interface réseau')
    parser.add_argument('-a', '--api', required=True, help='URL API')
    parser.add_argument('-k', '--key', required=True, help='Clé API')
    parser.add_argument('-w', '--workers', type=int, default=3, help='Threads')
    parser.add_argument('-c', '--count', type=int, default=0)
    parser.add_argument('-t', '--timeout', type=int, default=None)
    parser.add_argument('-f', '--filter', default='udp port 161 or udp port 162')
    parser.add_argument('-q', '--quiet', action='store_true')
    
    args = parser.parse_args()
    
    interface = args.interface
    if not interface:
        interface = get_best_interface()
        logger.info(f"Interface auto-sélectionnée: {interface}")

    sniffer = SNMPSnifferMultithreading(
        interface=interface,
        filter_expr=args.filter,
        api_endpoint=args.api,
        api_key=args.key,
        num_workers=args.workers,
        verbose=not args.quiet
    )
    
    try:
        sniffer.start(packet_count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        sniffer.stop()

if __name__ == '__main__':
    main()