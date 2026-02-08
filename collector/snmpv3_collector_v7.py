#!/usr/bin/env python3
"""
SNMPv3 Collector - pysnmp 7.1.22 compatible
Collecte les donnees SNMP d'un switch et les envoie a l'API
"""

import os
import sys
import json
import argparse
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

try:
    # IMPORTS CRITIQUES pour pysnmp 7.x
    from pysnmp import SnmpEngine, hlapi
    from pysnmp.hlapi import (
        CommunityData,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        setCmd,
        nextCmd,
        bulkCmd,
    )
    from pysnmp.proto import rfc1902
except ImportError as e:
    print(f"ERREUR CRITIQUE: {e}")
    print("\nInstalle pysnmp 7.1.22:")
    print("  pip install pysnmp==7.1.22 pyopenssl cryptography")
    sys.exit(1)

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
    auth_protocol: str = "hmacSha"  # pysnmp 7.x: hmacSha ou hmacSha256
    priv_protocol: str = "aes"      # pysnmp 7.x: aes ou 3des
    username: str = "admin"
    auth_password: str = ""
    priv_password: str = ""


class SNMPv3Collector:
    """Collecteur SNMPv3 compatible pysnmp 7.1.22"""
    
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
            verbose: Affichage detaille
        """
        self.config = config
        self.mode = mode
        self.verbose = verbose
        self.snmp_engine = SnmpEngine()
        
        if self.verbose:
            logger.setLevel(logging.DEBUG)
            logger.debug(f"Mode: {mode.value}")
            logger.debug(f"Host: {config.host}:{config.port}")
            logger.debug(f"Auth: {config.auth_protocol}, Priv: {config.priv_protocol}")
    
    def get_oid(self, oid: str) -> Optional[Any]:
        """Recupere la valeur d'un OID
        
        Args:
            oid: OID a recuperer (ex: "1.3.6.1.2.1.1.5.0")
            
        Returns:
            Valeur de l'OID ou None
        """
        try:
            # Creer l'utilisateur SNMPv3
            user_data = UsmUserData(
                self.config.username,
                self.config.auth_password,
                self.config.priv_password,
                authProtocol=self.config.auth_protocol,
                privProtocol=self.config.priv_protocol,
            )
            
            # Configuration de la cible
            target = UdpTransportTarget(
                (self.config.host, self.config.port),
                timeout=self.config.timeout,
                retries=self.config.retries,
            )
            
            # Contexte SNMP
            context = ContextData()
            
            # Executer le GET
            iterator = getCmd(
                self.snmp_engine,
                user_data,
                target,
                context,
                ObjectType(ObjectIdentity(oid)),
            )
            
            # Recuperer le resultat
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
                logger.error(f"Exception lors du GET {oid}: {e}")
            return None
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Collecte les informations systeme de base
        
        Returns:
            Dict avec les donnees SNMP
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
            logger.info(f"  Recuperation {name}...")
            value = self.get_oid(oid)
            
            if value:
                data["results"][name] = value
                logger.info(f"    OK: {name} = {value[:50]}..." if len(str(value)) > 50 else f"    OK: {name} = {value}")
            else:
                logger.warning(f"    ERREUR: Impossible de recuperer {name}")
        
        return data
    
    def test_connection(self) -> bool:
        """Teste la connexion au device
        
        Returns:
            True si la connexion fonctionne
        """
        logger.info(f"Test de connexion a {self.config.host}:{self.config.port}...")
        
        result = self.get_oid(self.OIDS["sysDescr"])
        
        if result:
            logger.info("Connection OK!")
            logger.info(f"Device: {result}")
            return True
        else:
            logger.error("Connection FAILED!")
            return False


def main():
    """Point d'entree du script"""
    parser = argparse.ArgumentParser(
        description="SNMPv3 Collector - pysnmp 7.1.22",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Mode TEST (avec localhost)
  python snmpv3_collector_v7.py --mode test --verbose
  
  # Mode PRODUCTION
  python snmpv3_collector_v7.py --mode production --host 192.168.1.1 --username admin
  
  # Test de connexion
  python snmpv3_collector_v7.py --test-only
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["test", "production"],
        default="test",
        help="Mode de fonctionnement (defaut: test)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Adresse IP du device (defaut: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=161,
        help="Port SNMP (defaut: 161)"
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
        help="Affichage detaille"
    )
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Teste la connexion seulement"
    )
    
    args = parser.parse_args()
    
    # Creer la configuration
    config = SNMPConfig(
        host=args.host,
        port=args.port,
        username=args.username,
        auth_password=args.auth_pass,
        priv_password=args.priv_pass,
    )
    
    # Creer le collecteur
    mode = SNMPMode.TEST if args.mode == "test" else SNMPMode.PRODUCTION
    collector = SNMPv3Collector(config, mode=mode, verbose=args.verbose)
    
    # Executer
    try:
        if args.test_only:
            # Test de connexion uniquement
            success = collector.test_connection()
            sys.exit(0 if success else 1)
        else:
            # Collecte complete
            data = collector.collect_system_info()
            
            # Afficher les resultats
            print("\n" + "="*70)
            print("RESULTATS DE LA COLLECTE SNMP")
            print("="*70)
            print(json.dumps(data, indent=2))
            print("="*70)
            
            # Verifier si des donnees ont ete collectees
            if data["results"]:
                logger.info(f"Collecte reussie: {len(data['results'])} OIDs")
                sys.exit(0)
            else:
                logger.error("Aucun OID collecte")
                sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("\nArret demande par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
