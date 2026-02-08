#!/usr/bin/env python3
"""
Collecteur SNMPv3 - Version pysnmp 7.1.22+
🚨 COMPATIBLE WINDOWS POWERSHELL

Ce script collecte les OIDs SNMPv3 d'un switch/routeur
et les envoie à l'API FastAPI pour stockage en BD PostgreSQL.

Usage:
    python collector/snmpv3_collector_v7.py --mode test --verbose
    python collector/snmpv3_collector_v7.py --mode prod --target 192.168.1.1
"""

import asyncio
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import sys

# PySnmp 7.x imports
from pysnmp import *
from pysnmp.hlapi.v3arch.asyncio import *

# Local imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from collector.logger_config import setup_logger
from collector.oid_mappings import COLLECTION_TEST, COLLECTION_STANDARD, COLLECTION_FULL


class SNMPv3Collector:
    """
    Collecteur SNMPv3 pour pysnmp 7.1.22+
    """
    
    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 161,
        snmp_user: str = "labuser",
        auth_protocol: str = "hmac_sha",
        auth_key: str = "authpass",
        priv_protocol: str = "aes",
        priv_key: str = "privpass",
        engine_id: Optional[str] = None,
        timeout: int = 5,
        retries: int = 2,
        log_level: str = "INFO",
        verbose: bool = False
    ):
        """
        Initialise le collecteur SNMPv3
        
        Args:
            target_ip: IP du switch/routeur
            target_port: Port SNMP (161 par défaut)
            snmp_user: Nom d'utilisateur SNMPv3
            auth_protocol: hmac_sha ou hmac_md5
            auth_key: Clé d'authentification
            priv_protocol: aes, des ou 3des
            priv_key: Clé de chiffrement
            engine_id: Engine ID pour SNMPv3 (auto-généré si None)
            timeout: Timeout de connexion (secondes)
            retries: Nombre de retries
            log_level: Niveau de log (DEBUG, INFO, WARNING, ERROR)
            verbose: Afficher les logs en console
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        
        # Configuration SNMPv3
        self.snmp_user = snmp_user
        self.auth_protocol = auth_protocol
        self.auth_key = auth_key
        self.priv_protocol = priv_protocol
        self.priv_key = priv_key
        self.engine_id = engine_id or f"engineID-{datetime.now().timestamp()}"
        
        # Logger
        log_file = f"logs/collector_{datetime.now().strftime('%Y-%m-%d')}.log" if not verbose else None
        self.logger = setup_logger(
            name="SNMPv3Collector",
            level=log_level,
            log_file=log_file
        )
        
        # Engine SNMP (OBLIGATOIRE en pysnmp 7.x)
        self.engine = SnmpEngine()
        
        self.logger.info(f"Collecteur SNMPv3 initialisé")
        self.logger.info(f"  Cible: {target_ip}:{target_port}")
        self.logger.info(f"  Utilisateur: {snmp_user}")
        self.logger.info(f"  Auth: {auth_protocol}, Priv: {priv_protocol}")
    
    def _create_user_identity(self) -> UserIdentity:
        """
        Crée l'identité utilisateur SNMPv3 pour pysnmp 7.x
        
        Returns:
            UserIdentity: Identité configurée
        """
        # Map les protocoles d'authentification
        auth_proto_map = {
            "hmac_sha": AuthenticationProtocol.hmac_sha,
            "hmac_md5": AuthenticationProtocol.hmac_md5,
            "hmac_sha2_224": AuthenticationProtocol.hmac_sha2_224,
            "hmac_sha2_256": AuthenticationProtocol.hmac_sha2_256,
        }
        
        # Map les protocoles de chiffrement
        priv_proto_map = {
            "des": PrivacyProtocol.des,
            "3des": PrivacyProtocol.triple_des,
            "aes": PrivacyProtocol.aes,
            "aes192": PrivacyProtocol.aes192,
            "aes256": PrivacyProtocol.aes256,
        }
        
        # Créer l'identité
        user_identity = UserIdentity(self.snmp_user)
        
        # Configurer l'authentification
        auth_proto = auth_proto_map.get(self.auth_protocol, AuthenticationProtocol.hmac_sha)
        user_identity = user_identity.with_authentication_protocol(auth_proto)
        user_identity = user_identity.with_authentication_key(self.auth_key)
        
        # Configurer le chiffrement
        priv_proto = priv_proto_map.get(self.priv_protocol, PrivacyProtocol.aes)
        user_identity = user_identity.with_privacy_protocol(priv_proto)
        user_identity = user_identity.with_privacy_key(self.priv_key)
        
        return user_identity
    
    async def snmp_get(self, oid: str) -> Optional[Dict]:
        """
        Exécute un GET SNMPv3
        
        Args:
            oid: OID à récupérer (ex: "1.3.6.1.2.1.1.1.0")
        
        Returns:
            Dict avec {"oid": "...", "value": "...", "type": "...", "timestamp": "..."}
        """
        try:
            user_identity = self._create_user_identity()
            
            # Créer le générateur GET
            generator = GetCommandGenerator.create(
                self.engine,
                user_identity,
                None,  # context
                [oid]
            )
            
            # Exécuter la requête
            result = await self.engine.send(
                generator,
                UdpTransportTarget(
                    (self.target_ip, self.target_port),
                    timeout=self.timeout,
                    retries=self.retries
                )
            )
            
            if result:
                self.logger.debug(f"GET {oid} réussi")
                for name, value in result.items():
                    return {
                        "oid": oid,
                        "name": str(name),
                        "value": str(value),
                        "timestamp": datetime.now().isoformat(),
                        "type": "GET",
                        "status": "success"
                    }
            else:
                self.logger.warning(f"GET {oid}: pas de réponse")
                return None
        
        except Exception as e:
            self.logger.error(f"GET {oid} échoué: {type(e).__name__} - {e}")
            return None
    
    async def snmp_walk(self, oid_root: str, max_repetitions: int = 25) -> List[Dict]:
        """
        Exécute un WALK SNMPv3 (GET BULK)
        
        Args:
            oid_root: OID racine de la table (ex: "1.3.6.1.2.1.2.2.1")
            max_repetitions: Nombre d'entrées par req (25 par défaut)
        
        Returns:
            Liste de Dict avec les résultats
        """
        results = []
        try:
            user_identity = self._create_user_identity()
            
            # Créer le générateur WALK
            generator = GetBulkCommandGenerator.create(
                self.engine,
                user_identity,
                None,  # context
                0,     # non_repeaters
                max_repetitions,
                [oid_root]
            )
            
            # Exécuter la requête
            result = await self.engine.send(
                generator,
                UdpTransportTarget(
                    (self.target_ip, self.target_port),
                    timeout=self.timeout,
                    retries=self.retries
                )
            )
            
            if result:
                self.logger.debug(f"WALK {oid_root} réussi ({len(result)} entrées)")
                for name, value in result.items():
                    results.append({
                        "oid": str(name),
                        "value": str(value),
                        "timestamp": datetime.now().isoformat(),
                        "type": "WALK",
                        "status": "success"
                    })
            else:
                self.logger.warning(f"WALK {oid_root}: pas de réponse")
        
        except Exception as e:
            self.logger.error(f"WALK {oid_root} échoué: {type(e).__name__} - {e}")
        
        return results
    
    async def collect_mode_test(self) -> Dict:
        """
        Mode TEST: Collecte juste les OIDs basiques
        
        Returns:
            Dict avec résultats
        """
        self.logger.info("\n" + "="*60)
        self.logger.info("🧪 MODE TEST - Collecte OIDs basiques")
        self.logger.info("="*60)
        
        results = {
            "mode": "test",
            "timestamp": datetime.now().isoformat(),
            "target": f"{self.target_ip}:{self.target_port}",
            "oids_collected": [],
            "success_count": 0,
            "error_count": 0
        }
        
        # Collecter les OIDs basiques (COLLECTION_TEST)
        for oid, metadata in COLLECTION_TEST.items():
            self.logger.info(f"\n📄 Collecte {metadata['name']} ({oid})...")
            result = await self.snmp_get(oid)
            
            if result:
                self.logger.info(f"  ✅ Réussi: {result['value']}")
                results["oids_collected"].append(result)
                results["success_count"] += 1
            else:
                self.logger.warning(f"  ❌ Échoué")
                results["error_count"] += 1
        
        return results
    
    async def collect_mode_prod(self, collection_type: str = "standard") -> Dict:
        """
        Mode PRODUCTION: Collecte OIDs avancés
        
        Args:
            collection_type: "standard" ou "full"
        
        Returns:
            Dict avec résultats
        """
        self.logger.info("\n" + "="*60)
        self.logger.info(f"🎉 MODE PRODUCTION ({collection_type.upper()})")
        self.logger.info("="*60)
        
        # Sélectionner la collection
        if collection_type == "full":
            collection = COLLECTION_FULL
        else:
            collection = COLLECTION_STANDARD
        
        results = {
            "mode": "production",
            "collection_type": collection_type,
            "timestamp": datetime.now().isoformat(),
            "target": f"{self.target_ip}:{self.target_port}",
            "oids_collected": [],
            "tables_collected": [],
            "success_count": 0,
            "error_count": 0
        }
        
        for oid, metadata in collection.items():
            if metadata.get("type") == "table":
                # C'est une table → WALK
                self.logger.info(f"\n📊 Table {metadata['name']} ({oid})...")
                table_results = await self.snmp_walk(oid)
                if table_results:
                    self.logger.info(f"  ✅ {len(table_results)} entrées récupérées")
                    results["tables_collected"].append({
                        "oid": oid,
                        "name": metadata['name'],
                        "entries_count": len(table_results),
                        "entries": table_results
                    })
                    results["success_count"] += len(table_results)
                else:
                    self.logger.warning(f"  ❌ Erreur")
                    results["error_count"] += 1
            else:
                # OID scalaire → GET
                self.logger.info(f"\n📄 {metadata['name']} ({oid})...")
                result = await self.snmp_get(oid)
                if result:
                    self.logger.info(f"  ✅ {result['value']}")
                    results["oids_collected"].append(result)
                    results["success_count"] += 1
                else:
                    self.logger.warning(f"  ❌ Erreur")
                    results["error_count"] += 1
        
        return results
    
    async def run(self, mode: str = "test", collection_type: str = "standard"):
        """
        Lance le collecteur
        
        Args:
            mode: "test" ou "production"
            collection_type: "standard" ou "full" (si mode=production)
        """
        try:
            if mode == "test":
                results = await self.collect_mode_test()
            else:
                results = await self.collect_mode_prod(collection_type)
            
            # Afficher le résumé
            self.logger.info("\n" + "="*60)
            self.logger.info("🌟 RÉSUMÉ COLLECTION")
            self.logger.info("="*60)
            self.logger.info(f"  Mode: {results.get('mode', 'unknown')}")
            self.logger.info(f"  Target: {results.get('target', 'unknown')}")
            self.logger.info(f"  Réussi: {results['success_count']}")
            self.logger.info(f"  Échec: {results['error_count']}")
            
            # Sauvegarder les résultats
            output_file = f"collector_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            self.logger.info(f"  Fichier: {output_file}")
            
            return results
        
        except Exception as e:
            self.logger.critical(f"🚨 ERREUR CRITIQUE: {type(e).__name__} - {e}")
            raise


async def main():
    """
    Point d'entrée du script
    """
    parser = argparse.ArgumentParser(
        description="Collecteur SNMPv3 pour pysnmp 7.1.22+",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python collector/snmpv3_collector_v7.py --mode test --verbose
  python collector/snmpv3_collector_v7.py --mode prod --target 192.168.1.1 --collection standard
        """
    )
    
    parser.add_argument('--mode', default='test', choices=['test', 'production', 'prod'],
                        help='Mode d\'exécution (test ou production)')
    parser.add_argument('--target', default='127.0.0.1',
                        help='IP du switch/routeur SNMPv3 (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=161,
                        help='Port SNMP (default: 161)')
    parser.add_argument('--user', default='labuser',
                        help='Utilisateur SNMPv3 (default: labuser)')
    parser.add_argument('--auth-pass', default='authpass',
                        help='Clé d\'authentification (default: authpass)')
    parser.add_argument('--priv-pass', default='privpass',
                        help='Clé de chiffrement (default: privpass)')
    parser.add_argument('--auth-proto', default='hmac_sha', choices=['hmac_sha', 'hmac_md5'],
                        help='Protocole d\'authentification (default: hmac_sha)')
    parser.add_argument('--priv-proto', default='aes', choices=['des', '3des', 'aes', 'aes192', 'aes256'],
                        help='Protocole de chiffrement (default: aes)')
    parser.add_argument('--collection', default='standard', choices=['standard', 'full'],
                        help='Type de collection (default: standard, mode production seulement)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Timeout de connexion en secondes (default: 5)')
    parser.add_argument('--retries', type=int, default=2,
                        help='Nombre de retries (default: 2)')
    parser.add_argument('--verbose', action='store_true',
                        help='Afficher les logs en console (sans fichier)')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        help='Niveau de log (default: INFO)')
    
    args = parser.parse_args()
    
    # Normaliser le mode (prod = production)
    mode = 'production' if args.mode in ['prod', 'production'] else 'test'
    
    # Créer et lancer le collecteur
    collector = SNMPv3Collector(
        target_ip=args.target,
        target_port=args.port,
        snmp_user=args.user,
        auth_protocol=args.auth_proto,
        auth_key=args.auth_pass,
        priv_protocol=args.priv_proto,
        priv_key=args.priv_pass,
        timeout=args.timeout,
        retries=args.retries,
        log_level=args.log_level,
        verbose=args.verbose
    )
    
    # Exécuter
    await collector.run(mode=mode, collection_type=args.collection)


if __name__ == "__main__":
    print("🚀 Collecteur SNMPv3 - pysnmp 7.1.22+ - Windows PowerShell")
    print("="*60)
    
    asyncio.run(main())
