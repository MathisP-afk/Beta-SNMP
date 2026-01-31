# Beta-SNMP Quick Start Guide

## Installation Rapide (5 minutes)

### 1. Cloner et configurer

```bash
# Cloner le repo
git clone https://github.com/MathisP-afk/Beta-SNMP.git
cd Beta-SNMP

# Créer virtualenv (optionnel mais recommandé)
python3 -m venv venv
source venv/bin/activate  # sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

### 2. Configurer les targets SNMP

Le fichier `config/snmp_targets.json` est déjà pré-rempli avec vos credentials:

```json
{
  "targets": [
    {
      "name": "cisco_sg250",
      "ip_address": "192.168.1.28",
      "credentials": {
        "username": "Alleria_W",
        "auth_password": "Vereesa_W",
        "auth_protocol": "SHA",
        "priv_password": "Windrunner",
        "priv_protocol": "AES128"
      }
    }
  ]
}
```

## Utilisation

### SNMP Operations

#### 1. Lister les targets

```bash
python main.py snmp --list-targets
```

**Output:**
```
============================================================
Configured SNMP Targets
============================================================

Name: cisco_sg250
  IP: 192.168.1.28:161
  Version: v3
  User: Alleria_W
  Auth: SHA
  Priv: AES128
  Timeout: 5s | Retries: 3
============================================================
```

#### 2. Récupérer des informations système

```bash
python main.py snmp --target cisco_sg250 --system-info
```

**Output:**
```
[SYSTEM INFO]
  description    : Cisco Systems, Inc. SG250-08P 8-port Gigabit Smart Managed Switch
  object_id      : 1.3.6.1.4.1.9.2.1.76
  uptime         : 72:15:43.00
  contact        : Network Admin
  name           : SG250-08
  location       : Data Center
  services       : 78
```

#### 3. Récupérer les interfaces réseau

```bash
python main.py snmp --target cisco_sg250 --interfaces
```

#### 4. Query une OID spécifique

```bash
python main.py snmp --target cisco_sg250 --get 1.3.6.1.2.1.1.1.0
```

#### 5. Changer une valeur (SET)

```bash
python main.py snmp --target cisco_sg250 --set 1.3.6.1.2.1.1.6.0 "New Location"
```

#### 6. Walker une OID (WALK)

```bash
python main.py snmp --target cisco_sg250 --walk 1.3.6.1.2.1.2
```

### Configurable IPs

#### Changer l'IP d'une target

```bash
# Lors du lancement: mettre à jour l'IP du switch
python main.py snmp --update-ip cisco_sg250 192.168.1.50

# Vérifier
python main.py snmp --list-targets
```

#### Ajouter un nouveau switch

```bash
python main.py config --add switch_backup 10.0.0.5
```

### API Operations (HTTPS with Insecure Mode)

⚠️ **ATTENTION:** Le mode "insecure" désactive la vérification SSL. À utiliser UNIQUEMENT en développement/test!

#### 1. Test de santé API

```bash
python main.py api \
  --url https://api.example.com \
  --health \
  --insecure
```

#### 2. Récupérer des données (GET)

```bash
python main.py api \
  --url https://api.example.com \
  --endpoint /api/devices \
  --get \
  --insecure
```

**Output:**
```
[GET] https://api.example.com/api/devices
Result: {
  "devices": [
    {
      "id": 1,
      "name": "switch01",
      "ip": "192.168.1.28",
      "model": "SG250-08"
    }
  ]
}
```

#### 3. Créer une ressource (POST)

```bash
python main.py api \
  --url https://api.example.com \
  --endpoint /api/devices \
  --post \
  --data '{"name": "switch02", "ip": "192.168.1.30", "model": "SG250-08"}' \
  --insecure
```

## Utilisation en Python

### SNMP Client

```python
from config.snmp_config import SNMPConfigManager
from snmp.snmp_client import SNMPv3Client

# Charger la configuration
config = SNMPConfigManager()

# Récupérer un target
target = config.get_target("cisco_sg250")

# Créer le client SNMP
client = SNMPv3Client(target)

# GET operation
value = client.get("1.3.6.1.2.1.1.1.0")
print(f"System Description: {value}")

# SET operation
success = client.set("1.3.6.1.2.1.1.6.0", "New Location")

# Get system info
info = client.get_system_info()
for key, val in info.items():
    print(f"{key}: {val}")

# Get interfaces
interfaces = client.get_interfaces()
for idx, iface in interfaces.items():
    print(f"Interface {idx}: {iface['name']}")

# Fermer la session
client.close()
```

### API Client

```python
from api.api_client import create_insecure_client

# Créer un client API avec mode insecure
api_client = create_insecure_client(
    "https://api.example.com",
    timeout=10,
    max_retries=3,
)

# GET request
devices = api_client.get("/api/devices")
print(f"Found {len(devices['devices'])} devices")

# POST request
new_device = api_client.post(
    "/api/devices",
    json_data={
        "name": "switch03",
        "ip": "192.168.1.35",
        "model": "SG250-08"
    }
)
print(f"Created device: {new_device}")

# Health check
if api_client.health_check():
    print("✓ API is healthy")

api_client.close()
```

### Configuration Management

```python
from config.snmp_config import (
    SNMPConfigManager,
    SNMPTarget,
    create_snmpv3_from_config,
)

config = SNMPConfigManager()

# Ajouter un nouveau target
creds = create_snmpv3_from_config()
target = SNMPTarget(
    name="new_switch",
    ip_address="192.168.1.40",
    credentials=creds,
)
config.add_target(target)

# Mettre à jour l'IP
config.update_target_ip("new_switch", "10.0.0.40")

# Lister tous les targets
for target in config.get_all_targets():
    print(f"{target.name}: {target.ip_address}")

# Supprimer
config.remove_target("new_switch")
```

## Flux Complet: SNMP → API

Exemple: Scanner SNMP et synchroniser avec API

```python
from config.snmp_config import SNMPConfigManager
from snmp.snmp_client import SNMPv3Client
from api.api_client import create_insecure_client
import json

# 1. Récupérer les infos via SNMP
config = SNMPConfigManager()
target = config.get_target("cisco_sg250")
client = SNMPv3Client(target)

device_info = client.get_system_info()
interfaces = client.get_interfaces()
client.close()

# 2. Envoyer à l'API
api_client = create_insecure_client("https://api.example.com", insecure=True)

device_data = {
    "name": device_info.get('name'),
    "description": device_info.get('description'),
    "location": device_info.get('location'),
    "interfaces": len(interfaces),
    "uptime": device_info.get('uptime'),
}

result = api_client.post("/api/devices/update", json_data=device_data)
print(f"API Response: {result}")

api_client.close()
```

## Dépannage

### "SNMP Connection refused"

```bash
# Vérifier la connectivité
ping 192.168.1.28

# Vérifier le port SNMP
netstat -an | grep 161

# Vérifier les credentials
python main.py snmp --list-targets
```

### "SSL: CERTIFICATE_VERIFY_FAILED"

Ceci est attendu avec le mode insecure. Utilisez `--insecure`:

```bash
python main.py api --url https://... --get --insecure
```

### "Authentication failed"

Vérifier les credentials dans `config/snmp_targets.json`:
- `username`: Doit correspondre au switch
- `auth_password`: Utilisé pour générer la clé d'authentification
- `priv_password`: Utilisé pour générer la clé de chiffrement
- Protocoles: Doivent correspondre à la configuration du switch

### Activer les logs de debug

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

# Ensuite exécuter vos opérations
```

## Tests

```bash
# Lancer tous les tests
python -m pytest tests/

# Ou avec unittest
python -m unittest discover tests/

# Test spécifique
python -m pytest tests/test_config.py::TestSNMPv3Credentials
```

## Prochaines Étapes

1. ✅ SNMPv3 avec auth + privacy
2. ✅ IPs configurables
3. ✅ API HTTPS avec mode insecure
4. 📋 Implémenter la GUI (partie Étudiant 2)
5. 📋 Ajouter la base de données
6. 📋 Implémenter l'API REST complète

## Documentation Complète

Voir `IMPLEMENTATION_GUIDE.md` pour plus de détails.

## Support

Pour des questions:
- Voir `IMPLEMENTATION_GUIDE.md`
- Consulter les exemples dans `snmp/snmp_client.py` et `api/api_client.py`
- Lancer les tests pour comprendre l'utilisation

---

**Créé**: 31 Janvier 2026  
**Python**: 3.14+  
**Status**: Production Ready 🚀
