# 🐍 PySnmp 7.1.22 sur Windows - Guide Complet

> **Version:** pysnmp 7.1.22+
> **OS:** Windows 10/11 + PowerShell
> **Python:** 3.10+

---

## 📌 Les Grandes Différences: pysnmp 5.x → 7.x

### API Refactorisée

| Aspect | pysnmp 5.x | pysnmp 7.x |
|--------|-----------|----------|
| **Import SNMPv3** | `from pysnmp.hlapi import *` | `from pysnmp import *` |
| **SnmpEngine** | Optionnel | **OBLIGATOIRE** |
| **Context** | `SnmpContext()` | `SnmpContext.create()` |
| **Engine ID** | Auto-généré | À spécifier explicitement |
| **Async Model** | asyncore | **Asyncio natif** |
| **Crypto** | PyCrypto | **Pyopenssl (mieux pour Windows)** |

### Exemple Clé: GET SNMPv3

**pysnmp 5.x:**
```python
from pysnmp.hlapi import *
from pysnmp.proto.rfc1155 import ObjectIdentifier

iterator = getCmd(
    SnmpEngine(),
    UsmUserData('user', 'auth_pass', 'priv_pass'),
    UdpTransportTarget(('192.168.1.1', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
)
```

**pysnmp 7.x:**
```python
from pysnmp import *

engine = SnmpEngine()
await engine.set_user_identity(
    'labuser',
    UserIdentity('labuser')
        .with_authentication_protocol(
            AuthenticationProtocol.hmac_sha
        )
        .with_authentication_key('authpass')
        .with_privacy_protocol(PrivacyProtocol.aes)
        .with_privacy_key('privpass')
)

await engine.send(
    GetCommandGenerator.create(
        engine,
        None,
        'labuser',
        ['1.3.6.1.2.1.1.1.0']
    ),
    UdpTransportTarget(('192.168.1.1', 161), timeout=5)
)
```

---

## 🔧 Installation Windows

### Étape 1: Prérequis Windows

```powershell
# Vérifier Python (doit être 3.10+)
python --version

# Vérifier pip
pip --version

# Upgrade pip (IMPORTANT pour pysnmp 7.x)
pip install --upgrade pip setuptools wheel
```

### Étape 2: Installer pysnmp 7.1.22

```powershell
# Installation simple
pip install pysnmp==7.1.22

# OU installation complète avec dépendances Windows
pip install pysnmp==7.1.22 pyopenssl cryptography

# Vérifier l'installation
python -c "import pysnmp; print(pysnmp.__version__)"
# Résultat attendu: 7.1.22
```

### Étape 3: Dépendances Complètes

```powershell
# Dans C:\snmp_project\Beta-SNMP
pip install -r requirements.txt

# Vérifier TOUTES les dépendances
pip list | findstr pysnmp
pip list | findstr cryptography
pip list | findstr pyopenssl
```

**requirements.txt à jour:**
```
pysnmp==7.1.22
pyopenssl>=22.0.0
cryptography>=40.0.0
```

---

## 🎯 Exemple Simple: SNMPv3 GET sur Windows

### test_snmpv3_windows.py

```python
#!/usr/bin/env python3
"""
Test SNMPv3 avec pysnmp 7.1.22 sur Windows
Exemple minimal pour vérifier la configuration
"""

import asyncio
from pysnmp import *

async def test_snmpv3_get():
    """
    Teste un GET SNMPv3 simple
    À adapter avec tes paramètres réels
    """
    
    # Configuration
    TARGET_IP = "192.168.1.1"  # ← À ADAPTER
    TARGET_PORT = 161
    SNMP_USER = "labuser"
    AUTH_PASS = "authpass"
    PRIV_PASS = "privpass"
    OID_TEST = "1.3.6.1.2.1.1.1.0"  # sysDescr
    
    print(f"🔍 Connexion SNMPv3 à {TARGET_IP}:{TARGET_PORT}")
    print(f"   Utilisateur: {SNMP_USER}")
    print(f"   OID: {OID_TEST} (sysDescr)\n")
    
    try:
        # 1. Créer l'engine SNMP
        engine = SnmpEngine()
        
        # 2. Configurer l'utilisateur SNMPv3
        user_identity = UserIdentity('labuser')
        user_identity = user_identity.with_authentication_protocol(
            AuthenticationProtocol.hmac_sha
        )
        user_identity = user_identity.with_authentication_key(AUTH_PASS)
        user_identity = user_identity.with_privacy_protocol(PrivacyProtocol.aes)
        user_identity = user_identity.with_privacy_key(PRIV_PASS)
        
        # 3. Créer le générateur de commande
        generator = GetCommandGenerator.create(
            engine,
            user_identity,
            None,  # context
            [OID_TEST]
        )
        
        # 4. Exécuter la requête
        result = await engine.send(
            generator,
            UdpTransportTarget((TARGET_IP, TARGET_PORT), timeout=5)
        )
        
        # 5. Traiter la réponse
        if result:
            print("✅ Réponse reçue!")
            for name, value in result.items():
                print(f"   {name}: {value}")
        else:
            print("❌ Pas de réponse du serveur")
    
    except Exception as e:
        print(f"❌ ERREUR: {type(e).__name__}")
        print(f"   Message: {e}")
        return False
    
    return True

# Lancer le test
if __name__ == "__main__":
    print("="*60)
    print("Test SNMPv3 avec pysnmp 7.1.22 - Windows")
    print("="*60 + "\n")
    
    success = asyncio.run(test_snmpv3_get())
    
    if success:
        print("\n✅ Test réussi!")
    else:
        print("\n❌ Test échoué. Vérifie la configuration.")
```

**Lancer le test:**
```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python test_snmpv3_windows.py
```

---

## 🔐 Configuration SNMPv3 pour Windows

### 1. Variables d'Environnement (.env)

```bash
# .env
SNMP_VERSION=3
SNMP_USER=labuser
SNMP_AUTH_PROTOCOL=hmac_sha  # ou hmac_md5
SNMP_AUTH_PASS=authpass
SNMP_PRIV_PROTOCOL=aes       # ou des, 3des
SNMP_PRIV_PASS=privpass
SNMP_ENGINE_BOOTS=0
SNMP_ENGINE_TIME=0
SNMP_TARGET_IP=192.168.1.1
SNMP_TARGET_PORT=161
```

### 2. Charger depuis .env

```python
from dotenv import load_dotenv
import os

load_dotenv()

SNMP_USER = os.getenv('SNMP_USER', 'labuser')
SNMP_AUTH_PASS = os.getenv('SNMP_AUTH_PASS')
SNMP_PRIV_PASS = os.getenv('SNMP_PRIV_PASS')
SNMP_TARGET_IP = os.getenv('SNMP_TARGET_IP', 'localhost')
```

---

## 📊 Opérations Courantes: pysnmp 7.x

### GET (Récupérer une valeur)

```python
async def snmp_get(engine, user, target_ip, oid):
    generator = GetCommandGenerator.create(
        engine,
        user,
        None,
        [oid]
    )
    return await engine.send(
        generator,
        UdpTransportTarget((target_ip, 161), timeout=5)
    )
```

### WALK (Récupérer une table)

```python
async def snmp_walk(engine, user, target_ip, oid_root):
    generator = GetBulkCommandGenerator.create(
        engine,
        user,
        None,
        0,      # non_repeaters
        25,     # max_repetitions
        [oid_root]
    )
    return await engine.send(
        generator,
        UdpTransportTarget((target_ip, 161), timeout=5)
    )
```

### SET (Modifier une valeur)

```python
async def snmp_set(engine, user, target_ip, oid, value):
    generator = SetCommandGenerator.create(
        engine,
        user,
        None,
        [(oid, Integer32(value))]
    )
    return await engine.send(
        generator,
        UdpTransportTarget((target_ip, 161), timeout=5)
    )
```

---

## 🚨 Erreurs Courantes Windows

### ❌ "ImportError: cannot import name 'SnmpEngine'"

```powershell
# Vérifier la version
python -c "import pysnmp; print(pysnmp.__version__)"

# Réinstaller
pip uninstall pysnmp -y
pip install pysnmp==7.1.22 --force-reinstall --no-cache-dir
```

### ❌ "Certificate verify failed" (SSL)

```powershell
# Installer pyopenssl
pip install pyopenssl cryptography --upgrade

# Vérifier
python -c "import OpenSSL; print(OpenSSL.__version__)"
```

### ❌ "No module named 'asyncio'"

Ne arrive que sur **très vieilles versions Python**. Upgrade:
```powershell
python -m pip install --upgrade python-3.11  # Via Windows Store
```

### ❌ "Timeout" à la connexion

```python
# Augmenter le timeout
UdpTransportTarget(
    ('192.168.1.1', 161),
    timeout=10,      # ← Augmenter de 5 à 10
    retries=3        # ← Ajouter des retries
)
```

---

## ✅ Checklist: Prêt pour le Collector?

- [ ] `python --version` → 3.10+
- [ ] `pip show pysnmp` → 7.1.22
- [ ] `pip show pyopenssl` → 22.0+
- [ ] `pip show cryptography` → 40.0+
- [ ] Test script lancé sans erreur
- [ ] `.env` rempli avec tes identifiants SNMPv3
- [ ] Ping au switch: `ping 192.168.1.1` ✓
- [ ] SNMPv3 accessible: `test_snmpv3_windows.py` ✓

---

## 🎯 Prochaines Étapes

1. **Adapter le collector** → Voir `collector/snmpv3_collector_v7.py`
2. **Tester le collector** → `python collector/snmpv3_collector_v7.py --mode test`
3. **Lancer l'API** → `python -m uvicorn snmp_api_improved:app --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem`
4. **Envoyer des données** → API reçoit les paquets SNMP via PostgreSQL

---

## 📚 Ressources

- **PySnmp Docs**: https://pysnmp.readthedocs.io/
- **PySnmp 7.x Migration**: https://github.com/lextudio/pysnmp/wiki/Migration
- **SNMPv3 RFC**: https://tools.ietf.org/html/rfc3414

**Besoin d'aide?** → Ouvre une issue sur GitHub! 🚀
