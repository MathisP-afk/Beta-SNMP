"""
Collector SNMPv3 - Polling + Traps
Envoie les données collectées vers l'API HTTPS avec retry/batch
"""
import json
import logging
import time
import threading
import argparse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import requests
from urllib3.exceptions import InsecureRequestWarning

# Supprime les warnings de certificat auto-signé
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from pysnmp.hlapi import *
    from pysnmp.proto.rfc1902 import OctetString
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    print("❌ ERREUR: pysnmp non installé. Exécuter: pip install pysnmp==5.1.1")

from collector.snmp_config import SNMPConfig
from collector.oid_mappings import get_flat_oid_list, get_oid_name, COLLECTION_STANDARD
from collector.logger_config import setup_logger, get_default_log_file

@dataclass
class SNMPValue:
    """Représente une valeur SNMP collectée"""
    oid: str
    value: Any
    type: str
    timestamp: str
    
    def to_dict(self) -> dict:
        return asdict(self)

class SNMPv3Collector:
    """
    Collecteur SNMPv3 thread-safe
    - Polling des OIDs
    - Batch & Retry automatique
    - Envoi vers API HTTPS
    """
    
    def __init__(self, config: SNMPConfig, logger: Optional[logging.Logger] = None):
        """
        Args:
            config: Configuration SNMPv3
            logger: Logger (crée un par défaut si None)
        """
        self.config = config
        self.logger = logger or setup_logger(
            level=config.log_level,
            log_file=config.log_file
        )
        
        # État du collector
        self.running = False
        self.last_poll_time = None
        self.poll_count = 0
        self.error_count = 0
        
        # Queue des paquets à envoyer
        self.batch_queue: List[Dict] = []
        self.queue_lock = threading.Lock()
        
        # Threads
        self.poll_thread = None
        self.sender_thread = None
        
        self.logger.info(f"🔧 Collector initialisé: {config}")
    
    # ========================================================================
    # POLLING SNMP
    # ========================================================================
    
    def poll_oids(self, oid_list: List[str]) -> List[SNMPValue]:
        """
        Effectue un SNMP GETBULK sur une liste d'OIDs
        
        Args:
            oid_list: Liste d'OIDs à collecter
        
        Returns:
            List[SNMPValue]: Valeurs collectées
        """
        if not PYSNMP_AVAILABLE:
            self.logger.error("❌ pysnmp non disponible!")
            return []
        
        results = []
        
        try:
            # Créer le moteur de communauté SNMPv3
            engine = SnmpEngine()
            
            # Authentification SNMPv3 authPriv
            auth = UsmUserData(
                self.config.username,
                self.config.auth_password,
                self.config.priv_password,
                authProtocol=usmHMACMD5 if self.config.auth_protocol.lower() == "md5" else usmHMACSHAAuthProtocol,
                privProtocol=usmDESPrivProtocol if self.config.priv_protocol.lower() == "des" else usmAesCfb128Protocol,
            )
            
            # Cible SNMP
            target = UdpTransportTarget(
                (self.config.target_ip, self.config.target_port),
                timeout=self.config.timeout,
                retries=self.config.retry_count
            )
            
            # Contexte SNMP
            context = ContextData(
                contextName=OctetString(self.config.context_name),
                contextEngineId=OctetString(hexValue=self.config.engine_id) if self.config.engine_id else None
            )
            
            # Effectuer le GETBULK
            iterator = bulkCmd(
                engine,
                auth,
                target,
                context,
                0,  # nonRepeaters
                self.config.batch_size,  # maxRepetitions
                *[ObjectType(ObjectIdentity(oid)) for oid in oid_list],
                lexicographicMode=False
            )
            
            # Traiter les résultats
            for error_indication, error_status, error_index, var_binds in iterator:
                if error_indication:
                    self.logger.error(f"❌ Erreur SNMP: {error_indication}")
                    self.error_count += 1
                    break
                
                if error_status:
                    self.logger.warning(f"⚠️ Status erreur: {error_status.prettyPrint()}")
                    continue
                
                # Chaque var_bind est un tuple (oid, value)
                for var_bind in var_binds:
                    oid_str = str(var_bind)
                    value = var_bind
                    
                    # Déterminer le type de la valeur
                    value_type = type(value).__name__
                    
                    # Créer un SNMPValue
                    snmp_val = SNMPValue(
                        oid=oid_str,
                        value=str(value),
                        type=value_type,
                        timestamp=datetime.now().isoformat()
                    )
                    
                    results.append(snmp_val)
                    self.logger.debug(f"✓ Collecté: {get_oid_name(oid_str)} = {value}")
            
            self.logger.info(f"📊 Poll résultat: {len(results)} OIDs collectés")
            return results
        
        except Exception as e:
            self.logger.error(f"❌ Erreur lors du polling: {e}")
            self.error_count += 1
            return []
    
    # ========================================================================
    # ENVOI VERS L'API
    # ========================================================================
    
    def send_batch_to_api(self, batch: List[Dict]) -> bool:
        """
        Envoie un batch de paquets SNMPv3 vers l'API HTTPS
        
        Args:
            batch: Liste de paquets à envoyer
        
        Returns:
            bool: True si envoyé avec succès
        """
        if not batch:
            return True
        
        try:
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }
            
            endpoint = f"{self.config.api_base_url}/snmp/v3/add"
            
            success_count = 0
            for packet in batch:
                try:
                    response = requests.post(
                        endpoint,
                        json=packet,
                        headers=headers,
                        verify=False,  # Ignorer le certificat auto-signé
                        timeout=self.config.api_timeout
                    )
                    
                    if response.status_code == 200:
                        success_count += 1
                        self.logger.debug(f"✓ Paquet envoyé: {packet['oid_racine']}")
                    else:
                        self.logger.warning(f"⚠️ API retourna {response.status_code}: {response.text}")
                
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"❌ Erreur d'envoi API: {e}")
                    return False
            
            self.logger.info(f"📤 Envoyé: {success_count}/{len(batch)} paquets")
            return success_count == len(batch)
        
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'envoi: {e}")
            return False
    
    # ========================================================================
    # FORMATAGE PAYLOAD POUR L'API
    # ========================================================================
    
    def format_payload_v3(self, values: List[SNMPValue]) -> Dict:
        """
        Formate les valeurs SNMP en payload API v3
        
        Args:
            values: Valeurs collectées
        
        Returns:
            dict: Payload conforme à PostTrameSNMPv3
        """
        if not values:
            return {}
        
        # Utiliser le premier OID comme racine
        oid_racine = values.oid
        
        # Convertir les valeurs en varbinds
        varbinds = [
            {
                "oid": val.oid,
                "type": val.type,
                "value": val.value
            }
            for val in values
        ]
        
        payload = {
            "source_ip": self.config.target_ip,
            "source_port": self.config.target_port,
            "dest_ip": "192.168.1.87",  # PC Windows
            "dest_port": 162,
            "oid_racine": oid_racine,
            "type_pdu": "GetResponse",
            "contexte": self.config.context_name,
            "niveau_securite": self.config.security_level,
            "utilisateur": self.config.username,
            "request_id": int(time.time() * 1000) % 2147483647,  # PID basé sur timestamp
            "error_status": "0",
            "error_index": 0,
            "engine_id": self.config.engine_id or "",
            "contenu": {"varbinds": varbinds}
        }
        
        return payload
    
    # ========================================================================
    # THREADS
    # ========================================================================
    
    def _polling_loop(self, collection: str = "standard"):
        """Thread de polling périodique"""
        self.logger.info(f"🔄 Démarrage du polling ({self.config.poll_interval}s d'intervalle)")
        
        oid_list = get_flat_oid_list(collection)
        
        while self.running:
            try:
                # Collecter les OIDs
                values = self.poll_oids(oid_list)
                
                if values:
                    # Formater le payload
                    payload = self.format_payload_v3(values)
                    
                    # Ajouter à la queue
                    with self.queue_lock:
                        self.batch_queue.append(payload)
                    
                    self.poll_count += 1
                    self.last_poll_time = datetime.now()
                
                # Attendre avant le prochain poll
                time.sleep(self.config.poll_interval)
            
            except Exception as e:
                self.logger.error(f"❌ Erreur dans le loop de polling: {e}")
                time.sleep(self.config.poll_interval)
    
    def _sender_loop(self):
        """Thread d'envoi par batch"""
        self.logger.info(f"📤 Démarrage du sender (batch size: {self.config.batch_size})")
        
        while self.running:
            try:
                # Vérifier s'il y a des paquets à envoyer
                with self.queue_lock:
                    if len(self.batch_queue) >= self.config.batch_size:
                        # Extraire le batch
                        batch = self.batch_queue[:self.config.batch_size]
                        self.batch_queue = self.batch_queue[self.config.batch_size:]
                    else:
                        batch = []
                
                # Envoyer le batch si non vide
                if batch:
                    self.send_batch_to_api(batch)
                
                # Attendre un peu
                time.sleep(5)
            
            except Exception as e:
                self.logger.error(f"❌ Erreur dans le loop d'envoi: {e}")
                time.sleep(5)
    
    # ========================================================================
    # CONTRÔLE DU COLLECTOR
    # ========================================================================
    
    def start(self, collection: str = "standard"):
        """Démarre le collector"""
        if self.running:
            self.logger.warning("⚠️ Collector déjà en cours d'exécution")
            return
        
        self.logger.info(f"🚀 Démarrage du collector avec collection '{collection}'")
        self.running = True
        
        # Démarrer les threads
        self.poll_thread = threading.Thread(
            target=self._polling_loop,
            args=(collection,),
            daemon=False
        )
        self.poll_thread.start()
        
        self.sender_thread = threading.Thread(
            target=self._sender_loop,
            daemon=False
        )
        self.sender_thread.start()
    
    def stop(self):
        """Arrête le collector"""
        self.logger.info("⏹️ Arrêt du collector...")
        self.running = False
        
        # Attendre les threads
        if self.poll_thread:
            self.poll_thread.join(timeout=5)
        if self.sender_thread:
            self.sender_thread.join(timeout=5)
        
        # Envoyer les paquets restants
        with self.queue_lock:
            if self.batch_queue:
                self.logger.info(f"📤 Envoi des {len(self.batch_queue)} paquets restants...")
                self.send_batch_to_api(self.batch_queue)
        
        self.logger.info(f"✅ Arrêt terminé. Stats: {self.poll_count} polls, {self.error_count} erreurs")
    
    def status(self) -> dict:
        """Retourne l'état du collector"""
        return {
            "running": self.running,
            "poll_count": self.poll_count,
            "error_count": self.error_count,
            "queue_size": len(self.batch_queue),
            "last_poll": self.last_poll_time.isoformat() if self.last_poll_time else None
        }

# ============================================================================
# MAIN
# ============================================================================

def main():
    """Point d'entrée"""
    
    parser = argparse.ArgumentParser(description="Collector SNMPv3")
    parser.add_argument(
        "--mode",
        choices=["test", "production"],
        default="production",
        help="Mode d'exécution"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Mode verbeux (DEBUG)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Durée d'exécution en secondes (0 = infini)"
    )
    
    args = parser.parse_args()
    
    try:
        # Charger la config
        config = SNMPConfig.from_env()
        
        # Ajuster le log level
        if args.verbose:
            config.log_level = "DEBUG"
        
        # Mode test?
        collection = "test" if args.mode == "test" else "standard"
        
        # Créer et démarrer le collector
        collector = SNMPv3Collector(config)
        collector.start(collection=collection)
        
        print(f"\n✅ Collector démarré en mode '{args.mode}'")
        print(f"📍 Cible: {config.target_ip}:{config.target_port}")
        print(f"🔐 User: {config.username} ({config.security_level})")
        print(f"📤 API: {config.api_base_url}")
        print("\nAppuyer sur Ctrl+C pour arrêter...\n")
        
        # Boucle principale
        start_time = time.time()
        try:
            while True:
                time.sleep(1)
                
                # Afficher le statut toutes les 30 secondes
                if int(time.time()) % 30 == 0:
                    status = collector.status()
                    print(f"📊 Status: {status}")
                
                # Arrêter après durée si spécifiée
                if args.duration > 0 and (time.time() - start_time) > args.duration:
                    break
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Interruption détectée...")
        
        finally:
            collector.stop()
    
    except ValueError as e:
        print(f"❌ Erreur de configuration: {e}")
        exit(1)
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        exit(1)

if __name__ == "__main__":
    main()
