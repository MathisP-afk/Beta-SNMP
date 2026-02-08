#!/usr/bin/env python3
"""
Mock SNMP Agent - SNMPv3
Simule un device SNMP pour tester le collector localement
Sans avoir besoin d'un véritable switch/routeur
"""

import sys
import logging
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmtManager, context, usmUserEngineID
from pysnmp.carrier.asynsock import dgram
from pysnmp.proto import rfc1902, rfc1905

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MockSNMPAgent:
    """Mock Agent SNMP SNMPv3 avec données simulées"""
    
    # Données simulées (OID -> valeur)
    MIB_DATA = {
        '1.3.6.1.2.1.1.1.0': rfc1902.OctetString('Cisco IOS XE Software - Beta-SNMP Test Device v1.0'),
        '1.3.6.1.2.1.1.2.0': rfc1902.ObjectIdentifier('1.3.6.1.4.1.9.9.46.1'),  # Cisco Switch
        '1.3.6.1.2.1.1.3.0': rfc1902.TimeTicks(123456789),
        '1.3.6.1.2.1.1.4.0': rfc1902.OctetString('admin@arles.local'),
        '1.3.6.1.2.1.1.5.0': rfc1902.OctetString('MockSwitch-Arles-01'),
        '1.3.6.1.2.1.1.6.0': rfc1902.OctetString('Arles, Provence-Alpes-Côte d\'Azur, France'),
    }
    
    def __init__(self, host='127.0.0.1', port=161, username='admin', 
                 auth_pass='authPassword123', priv_pass='privPassword123'):
        """Initialise l'agent SNMP
        
        Args:
            host: Adresse IP d'écoute
            port: Port UDP (default 161, mais besoin d'admin pour <1024)
            username: Nom d'utilisateur SNMPv3
            auth_pass: Mot de passe authentification
            priv_pass: Mot de passe chiffrement
        """
        self.host = host
        self.port = port
        self.username = username
        self.auth_pass = auth_pass
        self.priv_pass = priv_pass
        
        logger.info(f"Initialisation Mock SNMP Agent...")
        
        # Créer l'engine SNMP
        try:
            self.snmp_engine = engine.SnmpEngine()
            logger.debug("SnmpEngine créé")
        except Exception as e:
            logger.error(f"Erreur création SnmpEngine: {e}")
            raise
        
        # Configurer le transport UDP
        try:
            transport = dgram.UdpTransport()
            
            # Si port < 1024, nécessite droits admin
            if self.port < 1024:
                logger.warning(f"Port {self.port} nécessite droits admin!")
                logger.info("  Conseil: Utiliser --port 1161 en sans admin")
            
            # Essayer d'ouvrir le port
            transport.openServerMode((self.host, self.port))
            self.snmp_engine.transportDispatcher.registerTransport(
                dgram.UdpTransport.supportedDomains[0],
                transport
            )
            logger.info(f"Transport UDP: {self.host}:{self.port} OK")
        except Exception as e:
            logger.error(f"Erreur configuration transport: {e}")
            if self.port < 1024:
                logger.error("Essayez: python mock_snmp_agent.py --port 1161")
            raise
        
        # Ajouter l'utilisateur SNMPv3
        try:
            config.addV3User(
                self.snmp_engine,
                self.username,
                config.usmHMACMD5AuthProtocol,
                self.auth_pass,
                config.usmDESPrivProtocol,
                self.priv_pass
            )
            logger.info(f"Utilisateur SNMPv3 '{self.username}' configuré")
        except Exception as e:
            logger.error(f"Erreur ajout utilisateur: {e}")
            raise
        
        # Configurer VACM (View-based Access Control Model)
        try:
            config.addVacmUser(
                self.snmp_engine,
                3,  # SNMPv3
                self.username,
                'authPriv',
                (1, 3, 6, 1, 2, 1, 1),  # View OID (system group)
                (1, 3, 6, 1, 2, 1, 1),  # View mask
                contextName=''
            )
            logger.info("VACM (View Access Control) configuré")
        except Exception as e:
            logger.error(f"Erreur configuration VACM: {e}")
            # Ne pas échouer sur VACM, essayer de continuer
        
        # Contexte SNMP
        try:
            self.snmp_context = context.SnmpContext(self.snmp_engine)
            logger.debug("Contexte SNMP créé")
        except Exception as e:
            logger.error(f"Erreur création contexte: {e}")
            raise
    
    def start(self):
        """Démarre l'agent SNMP"""
        try:
            logger.info("\n" + "="*70)
            logger.info("🎭  MOCK SNMP AGENT - SNMPv3 DÉMARRÉ")
            logger.info("="*70)
            logger.info(f"Adresse: {self.host}:{self.port}")
            logger.info(f"Utilisateur: {self.username}")
            logger.info(f"Auth: MD5 ({self.auth_pass})")
            logger.info(f"Priv: DES ({self.priv_pass})")
            logger.info("\nDonnées simulées:")
            for oid, value in self.MIB_DATA.items():
                logger.info(f"  {oid} = {value}")
            logger.info("\nEn attente de requêtes... (Ctrl+C pour arrêter)")
            logger.info("="*70 + "\n")
            
            # Lancer le dispatcher
            self.snmp_engine.transportDispatcher.jobStarted(1)
            self.snmp_engine.transportDispatcher.runDispatcher()
        
        except KeyboardInterrupt:
            logger.info("\n👋 Agent arrêté par l'utilisateur")
        except Exception as e:
            logger.error(f"Erreur lors du démarrage: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def stop(self):
        """Arrête l'agent SNMP"""
        try:
            self.snmp_engine.transportDispatcher.jobFinished(1)
            logger.info("Agent arrêté")
        except Exception as e:
            logger.error(f"Erreur arrêt: {e}")


def main():
    """Point d'entrée du script"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Mock SNMP Agent SNMPv3 pour tester Beta-SNMP localement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Port 1161 (pas besoin d'admin)
  python mock_snmp_agent.py --port 1161
  
  # Port standard 161 (admin nécessaire)
  python mock_snmp_agent.py --port 161
  
  # Config personnalisée
  python mock_snmp_agent.py --host 127.0.0.1 --port 1161 --username admin
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
        default=161,
        help='Port UDP (default: 161, mais 1161 plus facile sans admin)'
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
        agent = MockSNMPAgent(
            host=args.host,
            port=args.port,
            username=args.username,
            auth_pass=args.auth_pass,
            priv_pass=args.priv_pass
        )
        agent.start()
    except KeyboardInterrupt:
        logger.info("\n🌛 Agent terminé")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
