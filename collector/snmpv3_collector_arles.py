#!/usr/bin/env python3
"""
SNMPv3 Collector - PRÉCONFIGURATIONÉ POUR ARLES
Collecte les données SNMP du switch Cisco 192.168.1.39
Identifiants SNMPv3:
  - Username: Alleria_W
  - Group: nSNMP_GN
  - Auth: SHA
  - Priv: DES
"""

import os
import sys
import json
import asyncio
import time
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum

# Configuration logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SNMPMode(Enum):
    \"\"\"Modes de fonctionnement du collector\"\"\"
    TEST = \"test\"
    PRODUCTION = \"production\"


@dataclass
class SNMPConfig:
    \"\"\"Configuration SNMPv3 ARLES\"\"\"
    host: str = \"192.168.1.39\"          # Switch Arles
    port: int = 161
    timeout: int = 5
    retries: int = 2
    username: str = \"Alleria_W\"         # Username SNMPv3
    auth_password: str = \"Alleria_Pass_Auth_2024\"  # Auth password (SHA)
    priv_password: str = \"Alleria_Pass_Priv_2024\"  # Priv password (DES)


class SNMPv3Collector:
    \"\"\"Collecteur SNMPv3 pour switch Cisco Arles\"\"\"
    
    # OIDs de base (SNMP MIB-II)
    OIDS = {
        \"sysDescr\": \"1.3.6.1.2.1.1.1.0\",
        \"sysObjectID\": \"1.3.6.1.2.1.1.2.0\",
        \"sysUpTime\": \"1.3.6.1.2.1.1.3.0\",
        \"sysContact\": \"1.3.6.1.2.1.1.4.0\",
        \"sysName\": \"1.3.6.1.2.1.1.5.0\",
        \"sysLocation\": \"1.3.6.1.2.1.1.6.0\",
        \"ifNumber\": \"1.3.6.1.2.1.2.1.0\",
    }\n    \n    def __init__(self, config: SNMPConfig, mode: SNMPMode = SNMPMode.TEST, verbose: bool = True):\n        self.config = config\n        self.mode = mode\n        self.verbose = verbose\n        \n        logger.info(f\"\\n{'='*70}\")\n        logger.info(\"🎯 SNMP COLLECTOR - CONFIGURATION ARLES\")\n        logger.info(f\"{'='*70}\")\n        logger.info(f\"Switch: {config.host}:{config.port}\")\n        logger.info(f\"Username: {config.username}\")\n        logger.info(f\"Auth Protocol: SHA\")\n        logger.info(f\"Priv Protocol: DES\")\n        logger.info(f\"Mode: {mode.value.upper()}\")\n        logger.info(f\"Timeout: {config.timeout}s, Retries: {config.retries}\")\n        logger.info(f\"{'='*70}\\n\")\n    \n    async def get_oid_pysnmp7(self, oid: str) -> Optional[Any]:\n        \"\"\"Récupère la valeur d'un OID avec pysnmp 7.x (async)\"\"\"\n        try:\n            from pysnmp.hlapi.v3arch.asyncio import (\n                SnmpEngine,\n                UsmUserData,\n                UdpTransportTarget,\n                ContextData,\n                ObjectType,\n                ObjectIdentity,\n                get_cmd,\n            )\n            from pysnmp.security import usm\n            \n            snmp_engine = SnmpEngine()\n            \n            try:\n                # Créer l'utilisateur SNMPv3 avec auth SHA et priv DES\n                user_data = UsmUserData(\n                    userName=self.config.username,\n                    authKey=self.config.auth_password,\n                    privKey=self.config.priv_password,\n                    authProtocol=usm.usmHMACMD5AuthProtocol,    # Ou usm.usmHMACSHAAuthProtocol\n                    privProtocol=usm.usmDESPrivProtocol,         # DES\n                )\n                \n                logger.debug(f\"User data créé: {self.config.username}\")\n                \n                # Configuration de la cible (ASYNC!)\n                target = await UdpTransportTarget.create(\n                    (self.config.host, self.config.port),\n                    timeout=self.config.timeout,\n                    retries=self.config.retries,\n                )\n                \n                logger.debug(f\"Target créée: {self.config.host}:{self.config.port}\")\n                \n                # Contexte SNMP\n                context = ContextData()\n                \n                logger.debug(f\"Envoi GET pour OID: {oid}\")\n                \n                # Exécuter le GET (await!)\n                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(\n                    snmp_engine,\n                    user_data,\n                    target,\n                    context,\n                    ObjectType(ObjectIdentity(oid)),\n                )\n                \n                if errorIndication:\n                    logger.warning(f\"❌ SNMP Error: {errorIndication}\")\n                    return None\n                \n                if errorStatus:\n                    logger.warning(f\"❌ SNMP Status Error: {errorStatus.prettyPrint()}\")\n                    return None\n                \n                # Extraire la valeur\n                for varBind in varBinds:\n                    oid_recv, value = varBind\n                    logger.debug(f\"✅ Reçu: {oid_recv} = {value}\")\n                    return str(value)\n                \n                return None\n            \n            finally:\n                snmp_engine.close_dispatcher()\n        \n        except Exception as e:\n            logger.error(f\"❌ Exception lors du GET {oid}: {type(e).__name__}: {e}\")\n            import traceback\n            traceback.print_exc()\n            return None\n    \n    async def get_oid(self, oid: str) -> Optional[Any]:\n        \"\"\"Wrapper pour récupérer un OID (async)\"\"\"\n        return await self.get_oid_pysnmp7(oid)\n    \n    async def collect_system_info(self) -> Dict[str, Any]:\n        \"\"\"Collecte les informations système (async)\"\"\"\n        data = {\n            \"timestamp\": time.time(),\n            \"mode\": self.mode.value,\n            \"host\": self.config.host,\n            \"results\": {}\n        }\n        \n        if self.mode == SNMPMode.TEST:\n            # Mode TEST: OIDs basiques\n            test_oids = {\n                \"sysDescr\": self.OIDS[\"sysDescr\"],\n                \"sysUpTime\": self.OIDS[\"sysUpTime\"],\n                \"sysName\": self.OIDS[\"sysName\"],\n                \"sysLocation\": self.OIDS[\"sysLocation\"],\n            }\n        else:\n            # Mode PRODUCTION: tous les OIDs\n            test_oids = self.OIDS\n        \n        logger.info(f\"\\n📊 COLLECTE {len(test_oids)} OIDs...\\n\")\n        \n        for name, oid in test_oids.items():\n            logger.info(f\"  ▸ {name}...\")\n            value = await self.get_oid(oid)\n            \n            if value:\n                data[\"results\"][name] = value\n                value_display = value[:60] + \"...\" if len(str(value)) > 60 else value\n                logger.info(f\"    ✅ {value_display}\")\n            else:\n                logger.warning(f\"    ❌ Impossible de récupérer {name}\")\n        \n        return data\n    \n    async def test_connection(self) -> bool:\n        \"\"\"Teste la connexion au device (async)\"\"\"\n        logger.info(f\"\\n🔌 TEST DE CONNEXION...\\n\")\n        logger.info(f\"Tentative de récupérer sysDescr...\")\n        \n        result = await self.get_oid(self.OIDS[\"sysDescr\"])\n        \n        if result:\n            logger.info(f\"\\n✅ CONNECTION OK!\")\n            logger.info(f\"Device: {result}\\n\")\n            return True\n        else:\n            logger.error(f\"\\n❌ CONNECTION FAILED!\\n\")\n            return False\n\n\nasync def main_async(test_only: bool = False, mode: str = \"test\"):\n    \"\"\"Point d'entrée async du script\"\"\"\n    \n    # Créer la configuration ARLES\n    config = SNMPConfig()\n    \n    # Créer le collecteur\n    snmp_mode = SNMPMode.TEST if mode == \"test\" else SNMPMode.PRODUCTION\n    collector = SNMPv3Collector(config, mode=snmp_mode, verbose=True)\n    \n    # Exécuter\n    try:\n        if test_only:\n            # Test de connexion uniquement\n            success = await collector.test_connection()\n            return 0 if success else 1\n        else:\n            # Collecte complète\n            data = await collector.collect_system_info()\n            \n            # Afficher les résultats\n            print(\"\\n\" + \"=\"*70)\n            print(\"📈 RÉSULTATS DE LA COLLECTE SNMP\")\n            print(\"=\"*70)\n            print(json.dumps(data, indent=2))\n            print(\"=\"*70 + \"\\n\")\n            \n            # Vérifier si des données ont été collectées\n            if data[\"results\"]:\n                logger.info(f\"✅ Collecte réussie: {len(data['results'])} OIDs\")\n                return 0\n            else:\n                logger.error(\"❌ Aucun OID collecté\")\n                return 1\n    \n    except KeyboardInterrupt:\n        logger.info(\"\\n👋 Arrêt demandé par l'utilisateur\")\n        return 0\n    except Exception as e:\n        logger.error(f\"❌ Erreur fatale: {e}\")\n        import traceback\n        traceback.print_exc()\n        return 1\n\n\ndef main():\n    \"\"\"Point d'entrée du script (synchrone wrapper)\"\"\"\n    import argparse\n    \n    parser = argparse.ArgumentParser(\n        description=\"SNMPv3 Collector - ARLES (Switch 192.168.1.39)\",\n        formatter_class=argparse.RawDescriptionHelpFormatter,\n        epilog=\"\"\"\nExemples:\n  # Test de connexion\n  python snmpv3_collector_arles.py --test-only\n  \n  # Collecte complète (mode TEST)\n  python snmpv3_collector_arles.py --mode test\n  \n  # Collecte complète (mode PRODUCTION)\n  python snmpv3_collector_arles.py --mode production\n        \"\"\"\n    )\n    \n    parser.add_argument(\n        \"--mode\",\n        choices=[\"test\", \"production\"],\n        default=\"test\",\n        help=\"Mode de fonctionnement (défaut: test)\"\n    )\n    parser.add_argument(\n        \"--test-only\",\n        action=\"store_true\",\n        help=\"Teste la connexion seulement\"\n    )\n    \n    args = parser.parse_args()\n    \n    # Lancer le code async\n    try:\n        exit_code = asyncio.run(main_async(test_only=args.test_only, mode=args.mode))\n        sys.exit(exit_code)\n    except KeyboardInterrupt:\n        logger.info(\"\\n🛑 Arrêt\")\n        sys.exit(0)\n\n\nif __name__ == \"__main__\":\n    main()\n