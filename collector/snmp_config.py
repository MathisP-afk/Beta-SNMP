"""
Configuration SNMPv3 - Gestion des paramètres
Thread-safe et supportant les variables d'environnement
"""
import os
import logging
from dataclasses import dataclass
from dotenv import load_dotenv
from typing import Optional

# Charger .env au démarrage
load_dotenv()

logger = logging.getLogger(__name__)

@dataclass
class SNMPConfig:
    """Configuration SNMPv3"""
    
    # Cible SNMP
    target_ip: str
    target_port: int = 161
    
    # Credentials SNMPv3 (JAMAIS en dur!)
    username: str
    auth_password: str
    priv_password: str
    auth_protocol: str = "sha"           # sha, md5
    priv_protocol: str = "des"           # des, 3des, aes
    
    # Contexte SNMPv3
    engine_id: Optional[str] = None
    security_level: str = "authPriv"     # noAuthNoPriv, authNoPriv, authPriv
    context_name: str = "default"
    
    # Polling
    poll_interval: int = 30              # secondes
    batch_size: int = 50                 # nombre de OIDs par requête
    retry_count: int = 3
    timeout: int = 10                    # secondes par requête
    
    # API
    api_base_url: str = "https://localhost:8443"
    api_key: str = ""
    api_timeout: int = 30
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "SNMPConfig":
        """Charge la config depuis les variables d'environnement"""
        
        # Cible SNMP
        target_ip = os.getenv("SNMP_TARGET_IP", "192.168.1.39")
        target_port = int(os.getenv("SNMP_TARGET_PORT", "161"))
        
        # Credentials - JAMAIS hardcodées!
        username = os.getenv("SNMP_USERNAME", "Alleria_W")
        auth_password = os.getenv("SNMP_AUTH_PASS")
        priv_password = os.getenv("SNMP_PRIV_PASS")
        
        if not auth_password or not priv_password:
            raise ValueError("SNMP_AUTH_PASS et SNMP_PRIV_PASS requis dans .env")
        
        engine_id = os.getenv("SNMP_ENGINE_ID", "8000B8C305A4E2B4F99A")
        
        # API
        api_base_url = os.getenv("API_BASE_URL", "https://localhost:8443")
        api_key = os.getenv("API_KEY", "")
        
        if not api_key:
            logger.warning("⚠️ API_KEY non définie, API calls échoueront")
        
        # Collector
        poll_interval = int(os.getenv("COLLECTOR_POLL_INTERVAL", "30"))
        batch_size = int(os.getenv("COLLECTOR_BATCH_SIZE", "50"))
        retry_count = int(os.getenv("COLLECTOR_RETRY_COUNT", "3"))
        
        # Logging
        log_level = os.getenv("LOG_LEVEL", "INFO")
        log_file = os.getenv("LOG_FILE", None)
        
        return cls(
            target_ip=target_ip,
            target_port=target_port,
            username=username,
            auth_password=auth_password,
            priv_password=priv_password,
            engine_id=engine_id,
            poll_interval=poll_interval,
            batch_size=batch_size,
            retry_count=retry_count,
            api_base_url=api_base_url,
            api_key=api_key,
            log_level=log_level,
            log_file=log_file,
        )
    
    def __repr__(self) -> str:
        """Affichage sécurisé (pas de secrets!)"""
        return (
            f"SNMPConfig("
            f"target={self.target_ip}:{self.target_port}, "
            f"username={self.username}, "
            f"security_level={self.security_level}, "
            f"poll_interval={self.poll_interval}s"
            f")"
        )
