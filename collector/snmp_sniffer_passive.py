#!/usr/bin/env python3
"""
SNMP Passive Sniffer - Capture du trafic SNMP réel
Capture les paquets SNMP sur le réseau et les envoie à l'API
"""

import os
import sys
from scapy.all import sniff, UDP, IP
from pyasn1.codec.der import decoder
from pysnmp.proto import api
import requests
import json
from datetime import datetime
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SNMPSniffer:
    def __init__(self, api_url="https://localhost:8443", api_key=None, interface=None):
        self.api_url = api_url
        self.api_key = api_key or os.getenv("API_KEY")
        self.interface = interface
        self.packet_count = 0
        
        # Charger la clé API depuis .env si pas fournie
        if not self.api_key:
            try:
                from dotenv import load_dotenv
                load_dotenv()
                self.api_key = os.getenv("API_KEY")
            except:
                logger.warning("Pas de clé API trouvée - certaines fonctionnalités peuvent ne pas marcher")
    
    def parse_snmp_packet(self, packet):
        """Parse un paquet SNMP et extrait les informations"""
        try:
            if not packet.haslayer(UDP):
                return None
            
            # Ports SNMP standard
            if packet[UDP].sport not in [161, 162] and packet[UDP].dport not in [161, 162]:
                return None
            
            # Extraire les données
            snmp_data = bytes(packet[UDP].payload)
            
            # Décoder SNMP (basique - version, community pour v2c)
            try:
                # Essayer de décoder comme SNMP v1/v2c
                msg_ver = api.decodeMessageVersion(snmp_data)
                
                if msg_ver in (0, 1):  # SNMPv1 ou v2c
                    pdu = api.protoModules[msg_ver].Message()
                    pdu, _ = decoder.decode(snmp_data, asn1Spec=pdu)
                    
                    pdu_type = pdu.getComponentByPosition(0).prettyPrint()
                    community = pdu.getComponentByPosition(1).prettyPrint()
                    
                    # Extraire le PDU
                    pdu_content = pdu.getComponentByPosition(2)
                    request_id = int(pdu_content.getComponentByPosition(0))
                    error_status = int(pdu_content.getComponentByPosition(1))
                    error_index = int(pdu_content.getComponentByPosition(2))
                    
                    # Extraire VarBinds
                    varbinds = []
                    varbind_list = pdu_content.getComponentByPosition(3)
                    for idx in range(len(varbind_list)):
                        varbind = varbind_list.getComponentByPosition(idx)
                        oid = varbind.getComponentByPosition(0).prettyPrint()
                        val = varbind.getComponentByPosition(1).prettyPrint()
                        varbinds.append({"oid": oid, "value": val})
                    
                    return {
                        "version": "v2c" if msg_ver == 1 else "v1",
                        "source_ip": packet[IP].src,
                        "source_port": packet[UDP].sport,
                        "dest_ip": packet[IP].dst,
                        "dest_port": packet[UDP].dport,
                        "community": community,
                        "type_pdu": self.get_pdu_type_name(pdu_type),
                        "request_id": request_id,
                        "error_status": str(error_status),
                        "error_index": error_index,
                        "oid_racine": varbinds[0]["oid"] if varbinds else "unknown",
                        "contenu": {"varbinds": varbinds}
                    }
                    
                elif msg_ver == 3:  # SNMPv3
                    # Pour v3, c'est plus complexe (encrypted)
                    return {
                        "version": "v3",
                        "source_ip": packet[IP].src,
                        "source_port": packet[UDP].sport,
                        "dest_ip": packet[IP].dst,
                        "dest_port": packet[UDP].dport,
                        "type_pdu": "SNMPv3-Encrypted",
                        "request_id": 0,
                        "error_status": "0",
                        "error_index": 0,
                        "oid_racine": "1.3.6.1",
                        "contexte": "",
                        "niveau_securite": "authPriv",
                        "utilisateur": "unknown",
                        "contenu": {"raw": True}
                    }
                    
            except Exception as e:
                logger.debug(f"Erreur décodage SNMP: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Erreur parsing paquet: {e}")
            return None
    
    def get_pdu_type_name(self, pdu_type):
        """Convertit le type PDU en nom lisible"""
        pdu_types = {
            "0": "GET-REQUEST",
            "1": "GET-NEXT-REQUEST",
            "2": "GET-RESPONSE",
            "3": "SET-REQUEST",
            "4": "TRAP",
            "5": "GET-BULK-REQUEST",
            "6": "INFORM-REQUEST",
            "7": "TRAP-V2",
            "8": "REPORT"
        }
        return pdu_types.get(str(pdu_type), f"PDU-{pdu_type}")
    
    def send_to_api(self, data):
        """Envoie les données à l'API"""
        try:
            endpoint = f"{self.api_url}/snmp/v2c/add" if data.get("version") != "v3" else f"{self.api_url}/snmp/v3/add"
            
            headers = {
                "Content-Type": "application/json"
            }
            
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = requests.post(
                endpoint,
                json=data,
                headers=headers,
                verify=False,  # Pour le certificat self-signed
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Paquet envoyé à l'API: {data['type_pdu']} {data['source_ip']}→{data['dest_ip']}")
                return True
            else:
                logger.warning(f"⚠️ API error {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Erreur envoi API: {e}")
            return False
    
    def packet_callback(self, packet):
        """Callback appelé pour chaque paquet capturé"""
        parsed = self.parse_snmp_packet(packet)
        
        if parsed:
            self.packet_count += 1
            logger.info(f"📦 Paquet SNMP #{self.packet_count} capturé: {parsed['type_pdu']} - {parsed['source_ip']}:{parsed['source_port']} → {parsed['dest_ip']}:{parsed['dest_port']}")
            
            # Envoyer à l'API
            self.send_to_api(parsed)
    
    def start(self):
        """Démarre la capture"""
        logger.info("=" * 70)
        logger.info("🔍 SNMP PASSIVE SNIFFER - Démarrage")
        logger.info(f"Interface: {self.interface or 'Toutes'}")
        logger.info(f"API URL: {self.api_url}")
        logger.info("Filtrage: UDP ports 161, 162")
        logger.info("=" * 70)
        
        try:
            # Filtre BPF pour ne capturer que le trafic SNMP
            sniff(
                filter="udp port 161 or udp port 162",
                prn=self.packet_callback,
                iface=self.interface,
                store=False  # Ne pas stocker en mémoire
            )
        except KeyboardInterrupt:
            logger.info(f"\n⏹️  Arrêt du sniffer. Total paquets capturés: {self.packet_count}")
        except Exception as e:
            logger.error(f"❌ Erreur capture: {e}")
            logger.error("💡 Astuce: Lancez avec des privilèges admin (sudo/admin)")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SNMP Passive Sniffer")
    parser.add_argument("--api-url", default="https://localhost:8443", help="URL de l'API")
    parser.add_argument("--api-key", help="Clé API (ou via variable API_KEY)")
    parser.add_argument("--interface", "-i", help="Interface réseau à écouter")
    
    args = parser.parse_args()
    
    sniffer = SNMPSniffer(
        api_url=args.api_url,
        api_key=args.api_key,
        interface=args.interface
    )
    
    sniffer.start()
