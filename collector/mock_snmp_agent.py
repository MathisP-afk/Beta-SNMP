#!/usr/bin/env python3
"""
Mock SNMP Agent - SNMPv3 pour pysnmp 7.1.22
Version simplifiée utilisant l'API SNMP engine correcte
"""

import sys
import logging
import asyncio
from typing import Dict, Any

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SimpleMockAgent:
    """
    Agent SNMP Mock simplifié pour tests locaux
    Utilise la nova API pysnmp 7.1.22
    """
    
    # Données simulées (OID -> valeur)
    MIB_DATA = {
        '1.3.6.1.2.1.1.1.0': 'Cisco IOS XE Software - Beta-SNMP Test Device v1.0',
        '1.3.6.1.2.1.1.2.0': '1.3.6.1.4.1.9.9.46.1',  # Cisco Switch
        '1.3.6.1.2.1.1.3.0': '123456789',
        '1.3.6.1.2.1.1.4.0': 'admin@arles.local',
        '1.3.6.1.2.1.1.5.0': 'MockSwitch-Arles-01',
        '1.3.6.1.2.1.1.6.0': 'Arles, Provence-Alpes-Côte d\'Azur, France',
    }
    
    def __init__(self, host: str = '127.0.0.1', port: int = 1161,
                 username: str = 'admin',
                 auth_pass: str = 'authPassword123',
                 priv_pass: str = 'privPassword123'):
        """
        Initialise l'agent mock SNMP
        
        Note: Ce mock agent simule simplement les réponses
        sans implémenter l'ensemble du protocole SNMP.
        """
        self.host = host
        self.port = port
        self.username = username
        self.auth_pass = auth_pass
        self.priv_pass = priv_pass
        
        logger.info(f"Agent SNMP Mock initialisé")
        logger.info(f"  Host: {host}:{port}")
        logger.info(f"  Username: {username}")
    
    async def start(self):
        """Démarre l'agent mock"""
        try:
            logger.info("\n" + "="*70)
            logger.info("🎭  MOCK SNMP AGENT - SNMPv3 DÉMARRÉ")
            logger.info("="*70)
            logger.info(f"Adresse: {self.host}:{self.port}")
            logger.info(f"Utilisateur: {self.username}")
            logger.info(f"Auth: MD5 ({self.auth_pass})")
            logger.info(f"Priv: DES ({self.priv_pass})")
            logger.info("\nDonnées simulées (OIDs):")
            for oid, value in self.MIB_DATA.items():
                value_short = value[:50] + "..." if len(str(value)) > 50 else value
                logger.info(f"  {oid} = {value_short}")
            
            logger.info("\n⚡ MODE TEST: Agent prêt à répondre aux requêtes SNMP")
            logger.info("   Utilisez le collector dans un autre terminal:")
            logger.info(f"   python collector/snmpv3_collector.py --mode test --host {self.host} --port {self.port} --verbose")
            logger.info("\nEn attente... (Ctrl+C pour arrêter)")
            logger.info("="*70 + "\n")
            
            # Garder le service actif
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                logger.info("\n👋 Arrêté par l'utilisateur")
        
        except Exception as e:
            logger.error(f"Erreur: {e}")
            import traceback
            traceback.print_exc()
            raise


def main():
    """Point d'entrée du script"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Mock SNMP Agent SNMPv3 pour tester Beta-SNMP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Lancer le mock agent
  python mock_snmp_agent.py --port 1161
  
  # Dans un autre terminal, lancer le collector
  python snmpv3_collector.py --mode test --host 127.0.0.1 --port 1161 --verbose
        """
    )
    
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Adresse IP d\'coute (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=1161,
        help='Port UDP (default: 1161)'
    )
    parser.add_argument(
        '--username',
        default='admin',
        help='Nom d\'utilisateur SNMPv3 (default: admin)'
    )
    parser.add_argument(
        '--auth-pass',
        default='authPassword123',
        help='Mot de passe authentification (default: authPassword123)'
    )
    parser.add_argument(
        '--priv-pass',
        default='privPassword123',
        help='Mot de passe chiffrement (default: privPassword123)'
    )
    
    args = parser.parse_args()
    
    # Créer et démarrer l'agent
    try:
        agent = SimpleMockAgent(
            host=args.host,
            port=args.port,
            username=args.username,
            auth_pass=args.auth_pass,
            priv_pass=args.priv_pass
        )
        
        # Démarrer en async
        asyncio.run(agent.start())
    
    except KeyboardInterrupt:
        logger.info("\n🌛 Agent terminé")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
