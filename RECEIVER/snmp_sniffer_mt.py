#!/usr/bin/env python3
"""
SNMP Packet Sniffer v2 - Multithreading + API HTTP + Authentification
Auteur: Étudiant 1 - Réseaux & Télécoms RT3
Projet: SAE 501-502 - Gestion de trames SNMP v2c (puis v3)
Description: Capture et traitement asynchrone avec envoi via API HTTP
Compatibilité: Windows, Linux (interfaces réseau adaptées)
VERSION: 3.1 - Format API corrigé & Lifecycle rétabli
"""

from scapy.all import *
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

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class SNMPPacketQueue:
    """
    Queue thread-safe pour gérer les paquets SNMP
    Permet la capture et le traitement asynchrone
    """
    
    def __init__(self, max_size=1000):
        """
        Initialise la queue
        Args:
            max_size (int): Taille maximale de la queue
        """
        self.queue = queue.Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.packet_count = 0
        self.stats = defaultdict(int)
    
    def put_packet(self, packet_info: Dict):
        """Ajoute un paquet à la queue"""
        try:
            self.queue.put_nowait(packet_info)
            with self.lock:
                self.packet_count += 1
        except queue.Full:
            logger.warning(f"[QUEUE] File pleine, paquet ignoré")
    
    def get_packet(self, timeout=1.0) -> Optional[Dict]:
        """Récupère un paquet de la queue"""
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def size(self):
        """Retourne la taille actuelle de la queue"""
        return self.queue.qsize()
    
    def get_stats(self):
        """Retourne les statistiques"""
        with self.lock:
            return {
                'total_queued': self.packet_count,
                'current_size': self.queue.qsize(),
                'stats': dict(self.stats)
            }


class SNMPSnifferMultithreading:
    """
    Sniffer SNMP avec support multithreading
    Optimisé pour API FastAPI avec Session HTTP persistante
    """
    
    def __init__(self, interface: str, filter_expr: str, 
                 api_endpoint: str, api_key: str,
                 num_workers: int = 3, 
                 verbose: bool = True):
        
        self.interface = interface
        self.filter_expr = filter_expr
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.num_workers = num_workers
        self.verbose = verbose
        
        # AUGMENTATION DE LA TAILLE DE LA QUEUE (Pour absorber les pics de trafic)
        self.packet_queue = SNMPPacketQueue(max_size=10000)
        
        self.running = True
        self.capture_thread = None
        self.worker_threads = []
        
        # Session HTTP persistante (Gros gain de performance)
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        })
        
        self.stats = {
            'total_captured': 0,
            'total_processed': 0,
            'api_sent': 0,
            'api_failed': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()
        
        logger.info(f"[INIT] Interface: {self.interface}")
        logger.info(f"[INIT] Queue Max: 10000 | Session HTTP active")

    def extract_snmp_oid_and_type(self, raw_data: bytes) -> tuple:
        """Extrait l'OID et le type PDU"""
        try:
            if len(raw_data) > 2:
                pdu_type_byte = raw_data[2]
                pdu_types = {
                    0xa0: 'GetRequest', 0xa1: 'GetNextRequest', 0xa2: 'GetResponse',
                    0xa3: 'SetRequest', 0xa4: 'Trap', 0xa5: 'GetBulkRequest',
                    0xa6: 'InformRequest', 0xa7: 'SNMPv2Trap'
                }
                pdu_type = pdu_types.get(pdu_type_byte, 'Unknown')
            else:
                pdu_type = 'Unknown'
            
            # OID par défaut si non parsé
            oid_string = "1.3.6.1.2.1.1.1.0" 
            return oid_string, pdu_type
        except Exception:
            return "1.3.6.1.0.0", "Unknown"
    
    def parse_snmp_packet(self, packet) -> Dict:
        """Parse un paquet SNMP et remplit TOUS les champs requis par l'API"""
        packet_info = {}
        
        try:
            # Valeurs par défaut obligatoires
            packet_info['source_ip'] = "0.0.0.0"
            packet_info['source_port'] = 161
            packet_info['dest_ip'] = "0.0.0.0"
            packet_info['dest_port'] = 162
            packet_info['community'] = "public"
            packet_info['oid_racine'] = "1.3.6.1.0.0"
            packet_info['type_pdu'] = "Unknown"
            packet_info['request_id'] = 0
            packet_info['error_status'] = "0"
            packet_info['error_index'] = 0
            packet_info['contenu'] = {}
            
            # Couche IP
            if IP in packet:
                packet_info['source_ip'] = packet[IP].src
                packet_info['dest_ip'] = packet[IP].dst
            
            # Couche UDP
            if UDP in packet:
                packet_info['source_port'] = packet[UDP].sport
                packet_info['dest_port'] = packet[UDP].dport
            
            # Parsing SNMP basique
            if Raw in packet:
                raw_data = bytes(packet[Raw].load)
                
                if b'public' in raw_data: packet_info['community'] = 'public'
                elif b'private' in raw_data: packet_info['community'] = 'private'
                
                oid, pdu_type = self.extract_snmp_oid_and_type(raw_data)
                packet_info['oid_racine'] = oid
                packet_info['type_pdu'] = pdu_type
                
                # ID Request simulé pour validation
                packet_info['request_id'] = int(time.time()) % 100000 

                packet_info['contenu'] = {
                    'raw_hex': raw_data.hex(),
                    'length': len(raw_data)
                }
        
        except Exception as e:
            logger.error(f"[PARSE] Erreur: {e}")
        
        return packet_info
    
    def packet_callback(self, packet):
        """Callback de capture"""
        packet_info = self.parse_snmp_packet(packet)
        self.packet_queue.put_packet(packet_info)
        
        with self.stats_lock:
            self.stats['total_captured'] += 1
        
        if self.verbose and self.stats['total_captured'] % 10 == 0:
             # Log réduit pour ne pas spammer la console
             pass

    def send_to_api(self, packets: List[Dict]) -> bool:
        """Envoie un lot de paquets via Session HTTP"""
        if not packets:
            return True
        
        url = f"{self.api_endpoint}/snmp/v2c/add"
        success_count = 0
        
        for packet in packets:
            try:
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
                    logger.warning(f"[API] Rejet {response.status_code}: {response.text[:100]}")
            
            except Exception as e:
                logger.error(f"[API] Erreur d'envoi: {e}")

        with self.stats_lock:
            self.stats['api_sent'] += success_count
            self.stats['api_failed'] += (len(packets) - success_count)
            
        return success_count > 0

    def worker_thread(self, worker_id: int, batch_size: int = 50, send_interval: float = 1.0):
        """Worker optimisé avec batchs"""
        logger.info(f"[WORKER-{worker_id}] Démarré (Batch: {batch_size})")
        
        batch = []
        last_send = time.time()
        
        while self.running:
            try:
                packet = self.packet_queue.get_packet(timeout=0.1)
                
                if packet:
                    batch.append(packet)
                    with self.stats_lock:
                        self.stats['total_processed'] += 1
                
                current_time = time.time()
                if len(batch) >= batch_size or (batch and current_time - last_send > send_interval):
                    self.send_to_api(batch)
                    batch = []
                    last_send = current_time
            
            except Exception as e:
                logger.error(f"[WORKER-{worker_id}] Crash: {e}")
                time.sleep(1)

    # =========================================================================
    # MÉTHODES DE GESTION DU THREADING (RÉINTÉGRÉES)
    # =========================================================================

    def capture_thread_func(self, packet_count: int = 0, timeout: Optional[int] = None):
        """Thread de capture Scapy"""
        logger.info(f"[CAPTURE-THREAD] Démarré")
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=self.packet_callback,
                count=packet_count,
                timeout=timeout,
                store=False
            )
        except PermissionError:
            logger.error("[CAPTURE] Permissions insuffisantes (sudo/root requis)")
        except Exception as e:
            logger.error(f"[CAPTURE] Erreur: {e}")
        finally:
            logger.info("[CAPTURE-THREAD] Arrêté")

    def start(self, packet_count: int = 0, timeout: Optional[int] = None):
        """Démarre la capture et les workers"""
        logger.info(f"[MAIN] Démarrage du sniffer multithreadé...")
        
        # Thread capture
        self.capture_thread = threading.Thread(
            target=self.capture_thread_func,
            args=(packet_count, timeout),
            daemon=False
        )
        self.capture_thread.start()
        
        # Threads workers (BATCH SIZE AUGMENTÉ A 50 ICI)
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self.worker_thread,
                args=(i, 50, 1.0),  # <--- Modification ici: batch=50, interval=1s
                daemon=False
            )
            worker.start()
            self.worker_threads.append(worker)
        
        logger.info(f"[MAIN] {self.num_workers} workers lancés")
        
        # Boucle d'affichage des stats
        try:
            while self.running:
                time.sleep(5)
                self.print_stats()
                if not self.capture_thread.is_alive() and self.packet_queue.size() == 0:
                    logger.info("[MAIN] Capture terminée et file vide.")
                    break
        except KeyboardInterrupt:
            logger.info("[MAIN] Arrêt demandé...")
            self.stop()

    def stop(self):
        """Arrête proprement"""
        logger.info("[MAIN] Arrêt du sniffer...")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        for worker in self.worker_threads:
            worker.join(timeout=2)
        self.print_final_stats()

    def print_stats(self):
        """Affiche les stats courantes"""
        with self.stats_lock:
            stats = self.stats.copy()
        queue_info = self.packet_queue.get_stats()
        logger.info(f"[STATS] Queue: {queue_info['current_size']} | "
                   f"Traités: {stats['total_processed']} | "
                   f"Envoyés OK: {stats['api_sent']} | "
                   f"Échecs: {stats['api_failed']}")

    def print_final_stats(self):
        """Affiche le bilan"""
        logger.info("="*40)
        logger.info("BILAN FINAL")
        with self.stats_lock:
            for k, v in self.stats.items():
                logger.info(f"{k}: {v}")
        logger.info("="*40)


def get_interface_windows():
    """Détecte l'interface Windows"""
    try:
        from scapy.arch import get_windows_if_list
        interfaces = get_windows_if_list()
        for iface in interfaces:
            if 'ASIX' in iface['description'] or 'Ethernet' in iface['description']:
                return iface['name']
        if interfaces: return interfaces[0]['name']
    except Exception as e:
        logger.error(f"[INTERFACE] Erreur: {e}")
    return None

def get_interface_linux():
    """Détecte l'interface Linux"""
    return 'eth0'

def main():
    """Main"""
    parser = argparse.ArgumentParser(description='SNMP Sniffer V3.1')
    parser.add_argument('-i', '--interface', default=None)
    parser.add_argument('-a', '--api', required=True)
    parser.add_argument('-k', '--key', required=True)
    parser.add_argument('-w', '--workers', type=int, default=3)
    parser.add_argument('-c', '--count', type=int, default=0)
    parser.add_argument('-t', '--timeout', type=int, default=None)
    parser.add_argument('-f', '--filter', default='udp port 161 or udp port 162')
    parser.add_argument('-q', '--quiet', action='store_true')
    
    args = parser.parse_args()
    
    interface = args.interface
    if not interface:
        import platform
        interface = get_interface_windows() if platform.system() == 'Windows' else get_interface_linux()
        if not interface:
            logger.error("Interface introuvable")
            sys.exit(1)
    
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