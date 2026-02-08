"""
Configuration du logging centralisée
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

def setup_logger(
    name: str = "snmpv3_collector",
    level: str = "INFO",
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configure le logger pour le collector
    
    Args:
        name: Nom du logger
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR)
        log_file: Chemin du fichier log (optionnel)
    
    Returns:
        logging.Logger: Logger configuré
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Format détaillé
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        datefmt="%d-%m-%Y %H:%M:%S"
    )
    
    # Handler Console (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Handler Fichier (optionnel)
    if log_file:
        # Créer le dossier logs s'il n'existe pas
        log_path = Path(log_file).parent
        log_path.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_default_log_file() -> str:
    """Génère un nom de fichier log horodaté"""
    return f"logs/collector_{datetime.now().strftime('%Y-%m-%d')}.log"
