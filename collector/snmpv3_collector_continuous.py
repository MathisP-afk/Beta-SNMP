#!/usr/bin/env python3
"""
SNMPv3 Continuous Collector - Production Mode
Collecte les donnees SNMP du switch en continu et les envoie a l'API
Version: 1.0 - Compatible pysnmp 7.1.22
"""

import os
import sys
import json
import argparse
import asyncio
import time
import aiohttp
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging
from datetime import datetime

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
    timeout: int = 5
    retries: int = 2
    username: str = "admin"
    auth_password: str = ""
    priv_password: str = ""


@dataclass
class APIConfig:
    """Configuration API"""
    host: str = "https://localhost:8443"
    verify_ssl: bool = False


class SNMPv3ContinuousCollector:
    """Collecteur SNMPv3 continu avec envoi API"""
    
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
    
    def __init__(self, snmp_config: SNMPConfig, api_config: APIConfig, mode: SNMPMode = SNMPMode.PRODUCTION, verbose: bool = False):
        """Initialise le collecteur continu
        
        Args:
            snmp_config: Configuration SNMPv3
            api_config: Configuration API
            mode: Mode TEST ou PRODUCTION
            verbose: Affichage detaille
        """
        self.snmp_config = snmp_config
        self.api_config = api_config
        self.mode = mode
        self.verbose = verbose
        self.cycle_count = 0
        self.total_success = 0
        self.total_errors = 0
        
        if self.verbose:
            logger.setLevel(logging.DEBUG)
            logger.debug(f"Mode: {mode.value}")
            logger.debug(f"SNMP Host: {snmp_config.host}:{snmp_config.port}")
            logger.debug(f"API Host: {api_config.host}")
    
    async def get_oid(self, oid: str) -> Optional[Any]:
        """Recupere la valeur d'un OID avec pysnmp 7.x (async)"""
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                SnmpEngine,
                UsmUserData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
                get_cmd,
                usmHMACSHAAuthProtocol,
                usmDESPrivProtocol,
            )
            
            snmp_engine = SnmpEngine()
            
            try:
                # Creer l'utilisateur SNMPv3 avec SHA + DES (comme SG250)
                user_data = UsmUserData(
                    userName=self.snmp_config.username,
                    authKey=self.snmp_config.auth_password,
                    authProtocol=usmHMACSHAAuthProtocol,
                    privKey=self.snmp_config.priv_password,
                    privProtocol=usmDESPrivProtocol,
                )
                
                # Configuration de la cible (ASYNC!)
                target = await UdpTransportTarget.create(
                    (self.snmp_config.host, self.snmp_config.port),
                    timeout=self.snmp_config.timeout,
                    retries=self.snmp_config.retries,
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
                        logger.warning(f"SNMP Error for {oid}: {errorIndication}")
                    return None
                
                if errorStatus:
                    if self.verbose:
                        logger.warning(f"SNMP Status Error for {oid}: {errorStatus.prettyPrint()}")
                    return None
                
                # Extraire la valeur
                for varBind in varBinds:
                    oid_recv, value = varBind
                    return str(value)
                
                return None
            
            finally:
                snmp_engine.close_dispatcher()
        
        except Exception as e:
            if self.verbose:
                logger.error(f"Exception lors du GET {oid}: {type(e).__name__}: {e}")
            return None
    
    async def collect_cycle(self) -> Dict[str, Any]:
        """Collecte un cycle de donnees SNMP (async)
        
        Returns:
            Dict avec les donnees collectees
        """
        self.cycle_count += 1
        
        data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cycle": self.cycle_count,
            "mode": self.mode.value,
            "host": self.snmp_config.host,
            "results": {},
            "success": True
        }
        
        # Determiner quels OIDs collecter selon le mode
        if self.mode == SNMPMode.TEST:
            oids_to_collect = {
                "sysDescr": self.OIDS["sysDescr"],
                "sysUpTime": self.OIDS["sysUpTime"],
                "sysName": self.OIDS["sysName"],
            }
        else:
            oids_to_collect = self.OIDS
        
        logger.info(f"[Cycle {self.cycle_count}] Collecte de {len(oids_to_collect)} OIDs...")
        
        # Collecter tous les OIDs en parallele (plus rapide)
        tasks = [
            (name, oid, self.get_oid(oid))
            for name, oid in oids_to_collect.items()
        ]
        
        for name, oid, task in tasks:
            try:
                value = await task
                if value:
                    data["results"][name] = value
                    logger.debug(f"  [{name}] = {value}")
                else:
                    logger.debug(f"  [{name}] = NULL")
                    data["results"][name] = None
            except Exception as e:
                logger.error(f"  [{name}] Erreur: {e}")
                data["results"][name] = None
        
        # Compter les resultats
        results_count = len([v for v in data["results"].values() if v is not None])
        logger.info(f"[Cycle {self.cycle_count}] {results_count}/{len(oids_to_collect)} OIDs collectes")
        
        return data
    
    async def send_to_api(self, data: Dict[str, Any]) -> bool:
        """Envoie les donnees a l'API (async)
        
        Args:
            data: Donnees a envoyer
            
        Returns:
            True si l'envoi reussit
        """
        try:
            # Configuration SSL
            connector = aiohttp.TCPConnector(verify_ssl=self.api_config.verify_ssl)
            
            async with aiohttp.ClientSession(connector=connector) as session:
                # Envoyer les donnees brutes
                url = f"{self.api_config.host}/api/snmp/data/ingest"
                
                headers = {
                    "Content-Type": "application/json"
                }
                
                if self.verbose:
                    logger.debug(f"POST {url}")
                    logger.debug(f"Data: {json.dumps(data, indent=2)[:200]}...")  # Preview
                
                async with session.post(
                    url,
                    json=data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status in [200, 201, 202]:
                        logger.info(f"[Cycle {self.cycle_count}] API Response: {response.status}")
                        self.total_success += 1
                        return True
                    else:
                        response_text = await response.text()
                        logger.warning(f"[Cycle {self.cycle_count}] API Error {response.status}: {response_text[:100]}")
                        self.total_errors += 1
                        return False
        
        except Exception as e:
            logger.error(f"[Cycle {self.cycle_count}] Exception lors de l'envoi API: {type(e).__name__}: {e}")
            self.total_errors += 1
            return False
    
    async def run_continuous(self, interval: int = 30):
        """Lance le collecteur en continu
        
        Args:
            interval: Intervalle entre les cycles en secondes
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"COLLECTOR CONTINU - Mode {self.mode.value.upper()}")
        logger.info(f"Host: {self.snmp_config.host}:{self.snmp_config.port}")
        logger.info(f"API: {self.api_config.host}")
        logger.info(f"Intervalle: {interval}s")
        logger.info(f"{'='*70}\n")
        
        try:
            cycle = 0
            while True:
                try:
                    # Collecter les donnees
                    data = await self.collect_cycle()
                    
                    # Envoyer a l'API
                    await self.send_to_api(data)
                    
                    # Statistiques
                    logger.info(f"[Statistiques] Success: {self.total_success}, Errors: {self.total_errors}")
                    
                    # Attendre le prochain cycle
                    logger.info(f"Attente {interval}s avant prochain cycle...\n")
                    await asyncio.sleep(interval)
                
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logger.error(f"Erreur dans la boucle: {e}")
                    await asyncio.sleep(interval)
        
        except KeyboardInterrupt:
            logger.info("\n\nArret du collector...")
            logger.info(f"Cycles executes: {self.cycle_count}")
            logger.info(f"Reussites: {self.total_success}")
            logger.info(f"Erreurs: {self.total_errors}")
            logger.info(f"Success rate: {100*self.total_success/(self.total_success+self.total_errors) if (self.total_success+self.total_errors) > 0 else 0:.1f}%")


async def main_async(args):
    """Point d'entree async du script"""
    
    snmp_config = SNMPConfig(
        host=args.host,
        port=args.port,
        username=args.username,
        auth_password=args.auth_pass,
        priv_password=args.priv_pass,
    )
    
    api_config = APIConfig(
        host=args.api_host,
        verify_ssl=args.api_verify_ssl
    )
    
    mode = SNMPMode.PRODUCTION if args.mode == "production" else SNMPMode.TEST
    
    collector = SNMPv3ContinuousCollector(
        snmp_config,
        api_config,
        mode=mode,
        verbose=args.verbose
    )
    
    # Lancer le collector continu
    await collector.run_continuous(interval=args.interval)


def main():
    """Point d'entree du script (synchrone wrapper)"""
    parser = argparse.ArgumentParser(
        description="SNMPv3 Continuous Collector - Production Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Mode TEST (intervalle court)
  python snmpv3_collector_continuous.py --mode test --interval 10 --verbose
  
  # Mode PRODUCTION (intervalle 30s)
  python snmpv3_collector_continuous.py --mode production --interval 30 --host 192.168.1.39
  
  # Custom interval (5s)
  python snmpv3_collector_continuous.py --interval 5
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["test", "production"],
        default="production",
        help="Mode de fonctionnement (defaut: production)"
    )
    parser.add_argument(
        "--host",
        default=os.getenv("SNMP_HOST", "192.168.1.39"),
        help="Adresse IP du device (defaut: 192.168.1.39)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("SNMP_PORT", "161")),
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
        "--interval",
        type=int,
        default=30,
        help="Intervalle entre les cycles en secondes (defaut: 30)"
    )
    parser.add_argument(
        "--api-host",
        default=os.getenv("API_HOST", "https://localhost:8443"),
        help="URL de l'API (defaut: https://localhost:8443)"
    )
    parser.add_argument(
        "--api-verify-ssl",
        action="store_true",
        help="Verifier le certificat SSL de l'API (defaut: False)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Affichage detaille"
    )
    
    args = parser.parse_args()
    
    # Lancer le code async
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logger.info("Arret")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
