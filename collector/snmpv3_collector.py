#!/usr/bin/env python3
"""
SNMPv3 Collector - pysnmp 7.1.22 FONCTIONNEL
Collecte les donnees SNMP d'un switch et les envoie a l'API
VERSION CORRIGEE: API async correcte pour pysnmp 7.1.22
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
        
        if self.verbose:
            logger.setLevel(logging.DEBUG)
            logger.debug(f"Mode: {mode.value}")
            logger.debug(f"Host: {config.host}:{config.port}")
    
    async def get_oid_pysnmp7(self, oid: str) -> Optional[Any]:
        """Recupere la valeur d'un OID avec pysnmp 7.x (async)
        
        Args:
            oid: OID a recuperer (ex: "1.3.6.1.2.1.1.5.0")
            
        Returns:
            Valeur de l'OID ou None
        """
        try:
            # Import dans la methode pour la flexibilite
            from pysnmp.hlapi.v3arch.asyncio import (
                SnmpEngine,
                UsmUserData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
                get_cmd,
            )
            
            snmp_engine = SnmpEngine()
            
            try:
                # Creer l'utilisateur SNMPv3
                user_data = UsmUserData(
                    userName=self.config.username,
                    authKey=self.config.auth_password,
                    privKey=self.config.priv_password,
                )
                
                # Configuration de la cible (ASYNC!)
                target = await UdpTransportTarget.create(
                    (self.config.host, self.config.port),
                    timeout=self.config.timeout,
                    retries=self.config.retries,
                )
                
                # Contexte SNMP
                context = ContextData()
                
                # Executer le GET (await!)
                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                    snmp_engine,
                    user_data,
                    target,
                    context,
                    ObjectType(ObjectIdentity(oid)),
                )
                
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
                
                return None
            
            finally:
                snmp_engine.close_dispatcher()
        
        except Exception as e:
            if self.verbose:
                logger.error(f"Exception lors du GET {oid}: {type(e).__name__}: {e}")
            return None
    
    async def get_oid(self, oid: str) -> Optional[Any]:
        """Wrapper pour recuperer un OID (async)"""
        return await self.get_oid_pysnmp7(oid)
    
    async def collect_system_info(self) -> Dict[str, Any]:
        """Collecte les informations systeme de base (async)
        
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
            value = await self.get_oid(oid)
            
            if value:
                data["results"][name] = value
                value_display = value[:50] + "..." if len(str(value)) > 50 else value
                logger.info(f"    OK: {name} = {value_display}")
            else:
                logger.warning(f"    ERREUR: Impossible de recuperer {name}")
        
        return data
    
    async def test_connection(self) -> bool:
        """Teste la connexion au device (async)
        
        Returns:
            True si la connexion fonctionne
        """
        logger.info(f"Test de connexion a {self.config.host}:{self.config.port}...")
        
        result = await self.get_oid(self.OIDS["sysDescr"])
        
        if result:
            logger.info("Connection OK!")
            logger.info(f"Device: {result}")
            return True
        else:
            logger.error("Connection FAILED!")
            return False


async def main_async(args):
    """Point d'entree async du script"""
    
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
            success = await collector.test_connection()
            return 0 if success else 1
        else:
            # Collecte complete
            data = await collector.collect_system_info()
            
            # Afficher les resultats
            print("\n" + "="*70)
            print("RESULTATS DE LA COLLECTE SNMP")
            print("="*70)
            print(json.dumps(data, indent=2))
            print("="*70)
            
            # Verifier si des donnees ont ete collectees
            if data["results"]:
                logger.info(f"Collecte reussie: {len(data['results'])} OIDs")
                return 0
            else:
                logger.error("Aucun OID collecte")
                return 1
    
    except KeyboardInterrupt:
        logger.info("\nArret demande par l'utilisateur")
        return 0
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Point d'entree du script (synchrone wrapper)"""
    parser = argparse.ArgumentParser(
        description="SNMPv3 Collector - pysnmp 7.1.22",
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
    
    # Lancer le code async
    try:
        exit_code = asyncio.run(main_async(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("\nArret")
        sys.exit(0)


if __name__ == "__main__":
    main()
