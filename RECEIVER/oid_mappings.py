"""
Mapping des OIDs SNMPv3 à collecter
Organiser par thème pour faciliter l'extensibilité
"""

# ============================================================================
# PHASE 1: OIDs BASIQUES (Mode Test) - À tester en premier
# ============================================================================

OID_BASIC = {
    "1.3.6.1.2.1.1.1.0": {
        "name": "sysDescr",
        "type": "string",
        "description": "Description du système"
    },
    "1.3.6.1.2.1.1.3.0": {
        "name": "sysUpTime",
        "type": "integer",
        "description": "Uptime (TimeTicks en 1/100ème de seconde)"
    },
    "1.3.6.1.2.1.1.5.0": {
        "name": "sysName",
        "type": "string",
        "description": "Nom FQDN du système"
    },
    "1.3.6.1.2.1.1.6.0": {
        "name": "sysLocation",
        "type": "string",
        "description": "Localisation physique"
    },
}

# ============================================================================
# PHASE 2: OIDs INTERFACES (Table ifTable)
# Utiliser WALK pour itérer les interfaces
# ============================================================================

OID_INTERFACES_TABLE = {
    "1.3.6.1.2.1.2.1.0": {
        "name": "ifNumber",
        "type": "integer",
        "description": "Nombre total d'interfaces"
    },
    "1.3.6.1.2.1.2.2.1": {
        "name": "ifEntry",
        "type": "table",
        "description": "Table des interfaces (entrées)",
        "columns": {
            "1": "ifIndex",
            "2": "ifDescr",
            "3": "ifType",
            "4": "ifMtu",
            "5": "ifSpeed",
            "6": "ifPhysAddress",
            "7": "ifAdminStatus",     # 1=up, 2=down, 3=testing
            "8": "ifOperStatus",      # 1=up, 2=down, 3=testing
            "10": "ifInOctets",       # Octets entrants (Counter32)
            "16": "ifOutOctets",      # Octets sortants (Counter32)
            "19": "ifOutDiscards",    # Paquets sortants jetés
        }
    },
}

# OID racine pour WALK sur toutes les interfaces
OID_INTERFACES_WALK = "1.3.6.1.2.1.2.2.1"

# ============================================================================
# PHASE 3: OIDs PERFORMANCE (Optionnel)
# ============================================================================

OID_PERFORMANCE = {
    "1.3.6.1.2.1.25.3.2.1.5.1": {
        "name": "hrProcessorLoad",
        "type": "integer",
        "description": "Charge CPU (0-100%)"
    },
    "1.3.6.1.2.1.25.2.2": {
        "name": "hrMemorySize",
        "type": "integer",
        "description": "Mémoire physique totale (bytes)"
    },
}

# ============================================================================
# COLLECTIONS PRÉDÉFINIES
# ============================================================================

# Collection pour mode TEST (rapide, peu d'OIDs)
COLLECTION_TEST = OID_BASIC

# Collection STANDARD (OIDs critiques)
COLLECTION_STANDARD = {
    **OID_BASIC,
    **OID_INTERFACES_TABLE,
}

# Collection COMPLÈTE (tout ce qui peut être utile)
COLLECTION_FULL = {
    **OID_BASIC,
    **OID_INTERFACES_TABLE,
    **OID_PERFORMANCE,
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_oid_list(collection_name: str = "standard") -> dict:
    """
    Retourne la liste des OIDs selon la collection
    
    Args:
        collection_name: "test", "standard", "full"
    
    Returns:
        dict: Mapping OID -> metadata
    """
    collections = {
        "test": COLLECTION_TEST,
        "standard": COLLECTION_STANDARD,
        "full": COLLECTION_FULL,
    }
    
    collection = collections.get(collection_name, COLLECTION_STANDARD)
    return collection

def get_flat_oid_list(collection_name: str = "standard") -> list:
    """
    Retourne une liste plate d'OIDs pour les requêtes SNMP
    
    Args:
        collection_name: "test", "standard", "full"
    
    Returns:
        list: ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", ...]
    """
    collection = get_oid_list(collection_name)
    # Exclure les entrées "table"
    return [oid for oid, meta in collection.items() if meta.get("type") != "table"]

def get_oid_name(oid: str) -> str:
    """Résoud un OID vers son nom humain"""
    all_oids = COLLECTION_FULL
    return all_oids.get(oid, {}).get("name", "UNKNOWN")
