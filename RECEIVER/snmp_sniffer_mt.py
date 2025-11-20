#!/usr/bin/env python3
"""
SNMP Packet Sniffer v2 - Multithreading + API HTTP + Authentification
Auteur: Étudiant 1 - Réseaux & Télécoms RT3
Projet: SAE 501-502 - Gestion de trames SNMP v2c (puis v3)
Description: Capture et traitement asynchrone avec envoi via API HTTP
Compatibilité: Windows, Linux (interfaces réseau adaptées)
VERSION: 3.0 - Format API corrigé
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
        """
        Ajoute un paquet à la queue
        
        Args:
            packet_info (dict): Informations du paquet
        """
        try:
            self.queue.put_nowait(packet_info)
            with self.lock:
                self.packet_count += 1
        except queue.Full:
            logger.warning(f"[QUEUE] File pleine, paquet ignoré")
    
    def get_packet(self, timeout=1.0) -> Optional[Dict]:
        """
        Récupère un paquet de la queue
        
        Args:
            timeout (float): Timeout en secondes
            
        Returns:
            dict: Paquet ou None si timeout
        """
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
    Thread 1: Capture des paquets
    Thread 2+: Traitement et envoi via API HTTP
    """
    
    def __init__(self, interface: str, filter_expr: str, 
                 api_endpoint: str, api_key: str,
                 num_workers: int = 3, 
                 verbose: bool = True):
        """
        Initialisation du sniffer multithreadé
        
        Args:
            interface (str): Interface réseau
            filter_expr (str): Filtre BPF
            api_endpoint (str): URL de l'API (ex: http://localhost:8000)
            api_key (str): Clé d'authentification API
            num_workers (int): Nombre de threads de traitement
            verbose (bool): Affichage détaillé
        """
        self.interface = interface
        self.filter_expr = filter_expr
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.num_workers = num_workers
        self.verbose = verbose
        
        # Queue thread-safe
        self.packet_queue = SNMPPacketQueue(max_size=5000)
        
        # Flags de contrôle
        self.running = True
        self.capture_thread = None
        self.worker_threads = []
        
        # Statistiques globales
        self.stats = {
            'total_captured': 0,
            'total_processed': 0,
            'api_sent': 0,
            'api_failed': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()
        
        logger.info(f"[INIT] Interface: {self.interface}")
        logger.info(f"[INIT] Filtre: {self.filter_expr}")
        logger.info(f"[INIT] API Endpoint: {self.api_endpoint}")
        logger.info(f"[INIT] Workers: {self.num_workers}")
        logger.info(f"[INIT] Authentification: Activée")
        logger.info(f"[INIT] Format API: SNMPv2c optimisé")
    
    def extract_snmp_oid_and_type(self, raw_data: bytes) -> tuple:
        """
        Extrait l'OID et le type PDU des données brutes SNMP
        
        Args:
            raw_data (bytes): Données brutes du paquet
            
        Returns:
            tuple: (oid_string, pdu_type_string)
        """
        try:
            # Détection très basique du type PDU (bytes 2-3)
            if len(raw_data) > 2:
                pdu_type_byte = raw_data[2]
                
                # Types PDU SNMP
                pdu_types = {
                    0x30: 'GetRequest',
                    0xa0: 'GetRequest',
                    0xa1: 'GetNextRequest',
                    0xa2: 'GetResponse',
                    0xa3: 'SetRequest',
                    0xa4: 'Trap',
                    0xa5: 'GetBulkRequest',
                    0xa6: 'InformRequest',
                    0xa7: 'SNMPv2Trap'
                }
                
                pdu_type = pdu_types.get(pdu_type_byte, 'Unknown')
            else:
                pdu_type = 'Unknown'
            
            # OID: chercher pattern typique (commençant par 1.3.6.1...)
            oid_string = "1.3.6.1.0.0"  # OID par défaut (sysUpTime)
            
            return oid_string, pdu_type
        
        except Exception as e:
            logger.error(f"[SNMP_PARSE] Erreur extraction OID: {e}")
            return "1.3.6.1.0.0", "Unknown"
    
    def parse_snmp_packet(self, packet) -> Dict:
        """
        Parse un paquet SNMP et formate pour l'API
        
        Args:
            packet: Paquet Scapy
            
        Returns:
            dict: Informations du paquet formatées pour API
        """
        packet_info = {}
        
        try:
            # Initialiser les champs obligatoires avec des valeurs par défaut
            packet_info['source_ip'] = "unknown"
            packet_info['source_port'] = 0
            packet_info['community'] = "public"
            packet_info['oid'] = "1.3.6.1.0.0"
            packet_info['type_pdu'] = "Unknown"
            packet_info['contenu'] = {}
            
            # Couche IP
            if IP in packet:
                packet_info['source_ip'] = packet[IP].src
            
            # Couche UDP
            if UDP in packet:
                packet_info['source_port'] = packet[UDP].sport
            
            # Extraction de la communauté SNMP et OID
            if Raw in packet:
                raw_data = bytes(packet[Raw].load)
                
                # Détection communauté
                if b'public' in raw_data:
                    packet_info['community'] = 'public'
                elif b'private' in raw_data:
                    packet_info['community'] = 'private'
                else:
                    packet_info['community'] = 'unknown'
                
                # Extraction OID et Type PDU
                oid, pdu_type = self.extract_snmp_oid_and_type(raw_data)
                packet_info['oid'] = oid
                packet_info['type_pdu'] = pdu_type
                
                # Contenu: données hex brutes
                packet_info['contenu'] = {
                    'raw_hex': raw_data.hex(),
                    'length': len(raw_data)
                }
        
        except Exception as e:
            logger.error(f"[PARSE] Erreur: {e}")
            packet_info['error'] = str(e)
        
        return packet_info
    
    def packet_callback(self, packet):
        """
        Callback appelé pour chaque paquet capturé
        Ajoute le paquet à la queue pour traitement asynchrone
        
        Args:
            packet: Paquet Scapy
        """
        packet_info = self.parse_snmp_packet(packet)
        self.packet_queue.put_packet(packet_info)
        
        with self.stats_lock:
            self.stats['total_captured'] += 1
        
        if self.verbose:
            logger.info(f"[CAPTURE] {packet_info.get('source_ip')} "
                       f"(port {packet_info.get('source_port')}) | "
                       f"Type: {packet_info.get('type_pdu')} | "
                       f"Communauté: {packet_info.get('community')}")
    
    def send_to_api(self, packets: List[Dict]) -> bool:
        """
        Envoie un lot de paquets à l'API HTTP avec authentification
        Format API corrigé: source_ip, source_port, community, oid, type_pdu, contenu
        
        Args:
            packets (list): Liste de paquets
            
        Returns:
            bool: True si succès
        """
        if not packets:
            return True
        
        try:
            # Endpoint API
            url = f"{self.api_endpoint}/snmp/v2c/add"
            
            # En-têtes avec authentification Bearer Token
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            # Envoyer chaque paquet individuellement (format API exige un seul objet)
            for packet in packets:
                try:
                    # Préparer le payload JSON conforme au schéma API
                    payload = {
                        'source_ip': packet.get('source_ip', 'unknown'),
                        'source_port': packet.get('source_port', 0),
                        'community': packet.get('community', 'public'),
                        'oid': packet.get('oid', '1.3.6.1.0.0'),
                        'type_pdu': packet.get('type_pdu', 'Unknown'),
                        'contenu': packet.get('contenu', {})
                    }
                    
                    # Envoi HTTP POST
                    response = requests.post(
                        url,
                        json=payload,
                        timeout=5,
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        with self.stats_lock:
                            self.stats['api_sent'] += 1
                    else:
                        logger.error(f"[API] Erreur {response.status_code}: "
                                   f"{response.text[:100]}")
                        with self.stats_lock:
                            self.stats['api_failed'] += 1
                
                except Exception as e_inner:
                    logger.error(f"[API] Erreur inner: {e_inner}")
                    with self.stats_lock:
                        self.stats['api_failed'] += 1
            
            # Log résumé
            logger.info(f"[API] Lot de {len(packets)} paquets traité")
            return True
        
        except requests.exceptions.Timeout:
            logger.error(f"[API] Timeout lors de l'envoi")
            with self.stats_lock:
                self.stats['api_failed'] += len(packets)
            return False
        
        except requests.exceptions.ConnectionError as e:
            logger.error(f"[API] Erreur de connexion: {e}")
            with self.stats_lock:
                self.stats['api_failed'] += len(packets)
            return False
        
        except Exception as e:
            logger.error(f"[API] Erreur: {e}")
            with self.stats_lock:
                self.stats['api_failed'] += len(packets)
            return False
    
    def worker_thread(self, worker_id: int, batch_size: int = 10, 
                     send_interval: float = 2.0):
        """
        Thread worker pour traiter et envoyer les paquets
        
        Args:
            worker_id (int): ID du worker
            batch_size (int): Nombre de paquets par lot
            send_interval (float): Intervalle d'envoi en secondes
        """
        logger.info(f"[WORKER-{worker_id}] Démarré")
        
        batch = []
        last_send = time.time()
        
        while self.running:
            try:
                # Récupérer un paquet avec timeout
                packet = self.packet_queue.get_packet(timeout=0.5)
                
                if packet:
                    batch.append(packet)
                    with self.stats_lock:
                        self.stats['total_processed'] += 1
                
                # Envoyer le lot si:
                # 1. Taille atteinte OU
                # 2. Temps écoulé depuis dernier envoi
                current_time = time.time()
                should_send = (len(batch) >= batch_size or 
                             (batch and current_time - last_send > send_interval))
                
                if should_send and batch:
                    logger.info(f"[WORKER-{worker_id}] Envoi de {len(batch)} "
                               f"paquets (Queue: {self.packet_queue.size()})")
                    
                    self.send_to_api(batch)
                    batch = []
                    last_send = current_time
            
            except Exception as e:
                logger.error(f"[WORKER-{worker_id}] Erreur: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1
        
        # Envoyer les paquets restants avant de quitter
        if batch:
            logger.info(f"[WORKER-{worker_id}] Envoi final de {len(batch)} "
                       f"paquets")
            self.send_to_api(batch)
        
        logger.info(f"[WORKER-{worker_id}] Arrêté")
    
    def capture_thread_func(self, packet_count: int = 0, timeout: Optional[int] = None):
        """
        Thread de capture des paquets
        
        Args:
            packet_count (int): Nombre de paquets (0 = illimité)
            timeout (int): Timeout en secondes
        """
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
        """
        Démarre la capture et les workers
        
        Args:
            packet_count (int): Nombre de paquets à capturer
            timeout (int): Timeout de capture
        """
        logger.info(f"[MAIN] Démarrage du sniffer multithreadé...")
        
        # Lancer le thread de capture
        self.capture_thread = threading.Thread(
            target=self.capture_thread_func,
            args=(packet_count, timeout),
            daemon=False
        )
        self.capture_thread.start()
        
        # Lancer les worker threads
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self.worker_thread,
                args=(i, 10, 2.0),  # batch_size=10, send_interval=2s
                daemon=False
            )
            worker.start()
            self.worker_threads.append(worker)
        
        logger.info(f"[MAIN] {self.num_workers} workers lancés")
        
        # Afficher les statistiques toutes les 10 secondes
        try:
            while self.running:
                time.sleep(10)
                self.print_stats()
        except KeyboardInterrupt:
            logger.info("[MAIN] Arrêt demandé...")
            self.stop()
    
    def stop(self):
        """Arrête le sniffer et tous les threads"""
        logger.info("[MAIN] Arrêt du sniffer...")
        self.running = False
        
        # Attendre la fin des threads
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        for worker in self.worker_threads:
            worker.join(timeout=5)
        
        logger.info("[MAIN] Tous les threads arrêtés")
        self.print_final_stats()
    
    def print_stats(self):
        """Affiche les statistiques actuelles"""
        with self.stats_lock:
            stats = self.stats.copy()
        
        queue_info = self.packet_queue.get_stats()
        
        logger.info(f"[STATS] Capturés: {stats['total_captured']} | "
                   f"Traités: {stats['total_processed']} | "
                   f"Envoyés API: {stats['api_sent']} | "
                   f"Échecs API: {stats['api_failed']} | "
                   f"Queue: {queue_info['current_size']}")
    
    def print_final_stats(self):
        """Affiche les statistiques finales"""
        logger.info("\n" + "="*80)
        logger.info("STATISTIQUES FINALES")
        logger.info("="*80)
        
        with self.stats_lock:
            stats = self.stats.copy()
        
        logger.info(f"Total capturés       : {stats['total_captured']}")
        logger.info(f"Total traités        : {stats['total_processed']}")
        logger.info(f"Envoyés API          : {stats['api_sent']}")
        logger.info(f"Échecs API           : {stats['api_failed']}")
        logger.info(f"Erreurs              : {stats['errors']}")
        logger.info("="*80)


def get_interface_windows():
    """
    Détecte automatiquement l'interface réseau active sur Windows
    Retourne le nom Scapy de l'interface
    """
    try:
        from scapy.arch import get_windows_if_list
        interfaces = get_windows_if_list()
        
        logger.info("[INTERFACE] Interfaces disponibles sur Windows:")
        for iface in interfaces:
            logger.info(f"  - {iface['name']} ({iface['description']})")
        
        # Chercher l'interface Ethernet ASIX
        for iface in interfaces:
            if 'ASIX' in iface['description'] or 'Ethernet' in iface['description']:
                logger.info(f"[INTERFACE] Interface sélectionnée: {iface['name']}")
                return iface['name']
        
        # Sinon, retourner la première interface active
        if interfaces:
            logger.info(f"[INTERFACE] Interface par défaut: {interfaces[0]['name']}")
            return interfaces[0]['name']
    
    except Exception as e:
        logger.error(f"[INTERFACE] Erreur: {e}")
    
    return None


def get_interface_linux():
    """
    Détecte l'interface réseau active sur Linux
    """
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True)
        logger.info("[INTERFACE] Interfaces disponibles:")
        logger.info(result.stdout)
        return 'eth0'  # Défaut Linux
    except Exception as e:
        logger.error(f"[INTERFACE] Erreur: {e}")
        return 'eth0'


def main():
    """Fonction principale"""
    
    parser = argparse.ArgumentParser(
        description='SNMP Sniffer Multithreadé v3 (Windows & Linux)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python snmp_sniffer_mt.py -i "Ethernet" -a http://127.0.0.1:8000 -k QErEkuLV3ettcWT2GjG4egQIWgSWGvz9gQ74dHDF_wFUtVfZlo3yaYTSWqpcIZV9 -w 3
  python snmp_sniffer_mt.py -i eth0 -a http://api.server.local:8000 -k YOUR_API_KEY
  sudo python3 snmp_sniffer_mt.py -i wlan0 -a http://192.168.1.50:5000 -k YOUR_API_KEY -c 100
  
Notes:
  - Sur Windows: utiliser le nom Ethernet (ex: "Ethernet", "Wi-Fi")
  - Sur Linux: utiliser le nom d'interface (ex: eth0, wlan0, eno1)
  - L'API doit accepter POST sur /snmp/v2c/add
  - Nécessite sudo/root pour la capture
  - La clé API est obligatoire pour l'authentification
  - Format API v3: source_ip, source_port, community, oid, type_pdu, contenu
        """
    )
    
    parser.add_argument('-i', '--interface',
                       default=None,
                       help='Interface réseau (auto-détecté si absent)')
    
    parser.add_argument('-a', '--api',
                       required=True,
                       help='URL de l\'API HTTP (ex: http://127.0.0.1:8000)')
    
    parser.add_argument('-k', '--key',
                       required=True,
                       help='Clé d\'authentification API (Bearer Token)')
    
    parser.add_argument('-w', '--workers',
                       type=int,
                       default=3,
                       help='Nombre de threads workers (défaut: 3)')
    
    parser.add_argument('-c', '--count',
                       type=int,
                       default=0,
                       help='Nombre de paquets (0 = illimité)')
    
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=None,
                       help='Timeout en secondes')
    
    parser.add_argument('-f', '--filter',
                       default='udp port 161 or udp port 162',
                       help='Filtre BPF personnalisé')
    
    parser.add_argument('-q', '--quiet',
                       action='store_true',
                       help='Mode silencieux')
    
    args = parser.parse_args()
    
    # Détection automatique de l'interface si non spécifiée
    interface = args.interface
    if not interface:
        import platform
        if platform.system() == 'Windows':
            interface = get_interface_windows()
        else:
            interface = get_interface_linux()
        
        if not interface:
            logger.error("[ERREUR] Impossible de détecter l'interface réseau")
            sys.exit(1)
    
    # Créer le sniffer multithreadé
    sniffer = SNMPSnifferMultithreading(
        interface=interface,
        filter_expr=args.filter,
        api_endpoint=args.api,
        api_key=args.key,
        num_workers=args.workers,
        verbose=not args.quiet
    )
    
    # Démarrer
    try:
        sniffer.start(packet_count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        sniffer.stop()


if __name__ == '__main__':
    main()