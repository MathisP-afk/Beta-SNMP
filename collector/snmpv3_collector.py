#!/usr/bin/env python3
"""
SNMPv3 Collector - Optimisé pour Python 3.13 + pysnmp 7.1.22
Collecte les données SNMP d'un device et les affiche en JSON
API: pysnmp.hlapi.asyncio avec support Python 3.13+
"""

import os
import sys
import json
import argparse
import time
import asyncio
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SNMPMode(Enum):
    """Modes de fonctionnement du collector"""
    TEST = "test"
    PRODUCTION = "production"


@dataclass
class SNMPConfig:
    """Configuration SNMPv3"""
    host: str = "192.168.1.1"
    port: int = 161
    timeout: int = 2
    retries: int = 3
    username: str = "admin"
    auth_password: str = ""
    priv_password: str = ""


class SNMPv3Collector:
    """Collecteur SNMPv3 compatible pysnmp 7.1.22 + Python 3.13"""
    
    # OIDs de base (SNMP MIB-II)
    OIDS = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "ifNumber": "1.3.6.1.2.1.2.1.0",
    }
    
    def __init__(self, config: SNMPConfig, mode: SNMPMode = SNMPMode.TEST, verbose: bool = False):
        """Initialise le collecteur SNMPv3
        
        Args:
            config: Configuration SNMPv3
            mode: Mode TEST ou PRODUCTION
            verbose: Affichage détaillé
        """
        self.config = config
        self.mode = mode
        self.verbose = verbose
        
        # Vérifier que pysnmp est disponible
        try:
            import pysnmp
            logger.debug(f"pysnmp {pysnmp.__version__} chargé")
        except ImportError as e:
            logger.error(f"Impossible d'importer pysnmp: {e}")
            raise
        
        if self.verbose:
            logger.setLevel(logging.DEBUG)
            logger.debug(f"Mode: {mode.value}")
            logger.debug(f"Host: {config.host}:{config.port}")
    
    def get_oid_sync(self, oid: str) -> Optional[Any]:
        """Récupère la valeur d'un OID (synchrone, compatible Python 3.13)
        
        Args:
            oid: OID à récupérer (ex: "1.3.6.1.2.1.1.5.0")
            
        Returns:
            Valeur de l'OID ou None
        """
        try:
            # Import de l'API sync de pysnmp 7.x (COMPATIBLE PYTHON 3.13)
            from pysnmp.hlapi import (
                getCmd,
                SnmpEngine,
                UsmUserData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
            )
            
            # Créer le moteur SNMP
            snmp_engine = SnmpEngine()
            
            # Créer l'utilisateur SNMPv3
            user_data = UsmUserData(
                userName=self.config.username,
                authKey=self.config.auth_password,
                privKey=self.config.priv_password,
            )
            
            # Configuration de la cible
            target = UdpTransportTarget(
                (self.config.host, self.config.port),
                timeout=self.config.timeout,
                retries=self.config.retries,
            )
            
            # Contexte SNMP
            context = ContextData()
            
            # Exécuter le GET
            iterator = getCmd(
                snmp_engine,
                user_data,
                target,
                context,
                ObjectType(ObjectIdentity(oid)),
            )
            
            # Récupérer le résultat
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                if self.verbose:
                    logger.warning(f"SNMP Error: {errorIndication}")
                return None
            
            if errorStatus:
                if self.verbose:
                    logger.warning(f"SNMP Status Error: {errorStatus.prettyPrint()}")
                return None
            
            # Extraire la valeur
            for varBind in varBinds:
                oid_recv, value = varBind
                if self.verbose:
                    logger.debug(f"Received: {oid_recv} = {value}")
                return str(value)
        
        except Exception as e:
            if self.verbose:
                logger.error(f"Exception lors du GET sync {oid}: {e}")
            return None
    
    def get_oid(self, oid: str) -> Optional[Any]:
        """Wrapper pour récupérer un OID (synchrone)"""
        return self.get_oid_sync(oid)
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Collecte les informations système de base
        
        Returns:
            Dict avec les données SNMP
        """
        data = {
            "timestamp": time.time(),
            "mode": self.mode.value,
            "host": self.config.host,
            "results": {}
        }
        
        if self.mode == SNMPMode.TEST:
            # Mode TEST: OIDs basiques
            test_oids = {
                "sysDescr": self.OIDS["sysDescr"],
                "sysUpTime": self.OIDS["sysUpTime"],
                "sysName": self.OIDS["sysName"],
                "sysLocation": self.OIDS["sysLocation"],
            }
        else:
            # Mode PRODUCTION: tous les OIDs
            test_oids = self.OIDS
        
        logger.info(f"Collecte {len(test_oids)} OIDs en mode {self.mode.value}...")
        
        for name, oid in test_oids.items():
            logger.info(f"  Récupération {name}...")
            value = self.get_oid(oid)
            
            if value:
                data["results"][name] = value
                value_display = value[:50] + "..." if len(str(value)) > 50 else value
                logger.info(f"    OK: {name} = {value_display}")
            else:
                logger.warning(f"    ERREUR: Impossible de récupérer {name}")
        
        return data
    
    def test_connection(self) -> bool:
        """Teste la connexion au device
        
        Returns:
            True si la connexion fonctionne
        """
        logger.info(f"Test de connexion à {self.config.host}:{self.config.port}...")
        
        result = self.get_oid(self.OIDS["sysDescr"])
        
        if result:
            logger.info("Connection OK!")
            logger.info(f"Device: {result}")
            return True
        else:
            logger.error("Connection FAILED!")
            return False


def main():
    """Point d'entrée du script"""
    parser = argparse.ArgumentParser(
        description="SNMPv3 Collector - pysnmp 7.1.22 + Python 3.13",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Mode TEST (avec localhost)
  python snmpv3_collector.py --mode test --verbose
  
  # Mode PRODUCTION
  python snmpv3_collector.py --mode production --host 192.168.1.1 --username admin
  
  # Test de connexion
  python snmpv3_collector.py --test-only
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["test", "production"],
        default="test",
        help="Mode de fonctionnement (défaut: test)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Adresse IP du device (défaut: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=161,
        help="Port SNMP (défaut: 161)"
    )
    parser.add_argument(
        "--username",
        default=os.getenv("SNMP_USERNAME", "admin"),
        help="Nom d'utilisateur SNMPv3"
    )
    parser.add_argument(
        "--auth-pass",
        default=os.getenv("SNMP_AUTH_PASS", "authPassword123"),
        help="Mot de passe authentication"
    )
    parser.add_argument(
        "--priv-pass",
        default=os.getenv("SNMP_PRIV_PASS", "privPassword123"),
        help="Mot de passe encryption"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Affichage détaillé"
    )
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Teste la connexion seulement"
    )
    
    args = parser.parse_args()
    
    # Créer la configuration
    config = SNMPConfig(
        host=args.host,
        port=args.port,
        username=args.username,
        auth_password=args.auth_pass,
        priv_password=args.priv_pass,
    )
    
    # Créer le collecteur
    mode = SNMPMode.TEST if args.mode == "test" else SNMPMode.PRODUCTION
    collector = SNMPv3Collector(config, mode=mode, verbose=args.verbose)
    
    # Exécuter
    try:
        if args.test_only:
            # Test de connexion uniquement
            success = collector.test_connection()
            sys.exit(0 if success else 1)
        else:
            # Collecte complète
            data = collector.collect_system_info()
            
            # Afficher les résultats
            print("\n" + "="*70)
            print("RESULTATS DE LA COLLECTE SNMP")
            print("="*70)
            print(json.dumps(data, indent=2))
            print("="*70)
            
            # Vérifier si des données ont été collectées
            if data["results"]:
                logger.info(f"Collecte réussie: {len(data['results'])} OIDs")
                sys.exit(0)
            else:
                logger.error("Aucun OID collecté")
                sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("\nArrêt demandé par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
