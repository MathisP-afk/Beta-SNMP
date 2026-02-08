# 🚀 Déploiement Windows SNMPv3 pysnmp 7.1.22 - RÉSUMÉ

**Date:** 2026-02-08  
**Version:** Beta-SNMP SNMPv3 Collector v2  
**OS:** Windows 10/11 PowerShell  
**Python:** 3.10+  
**PySnmp:** 7.1.22+  

---

## 🌏 Vue d'Ensemble

Tu es passé à **pysnmp 7.1.22** et tu utilises **Windows PowerShell**. L'API de pysnmp a **complètement changé** par rapport à 5.x.

Ce déploiement crée un **collector SNMPv3 production-ready** qui:
- ✅ Collecte des OIDs sur switch/routeur
- ✅ Les envoie à une API FastAPI HTTPS
- ✅ Les stocke dans PostgreSQL
- ✅ Fonctionne 100% sur Windows

---

## 📄 Fichiers Créés

### 1. 📃 **QUICKSTART_WINDOWS.md**
**Point d'entrée principal pour Windows**

- Menu: "Quelle est ta situation?"
- Lien vers script test automatique
- Architecture 3 terminaux
- Erreurs courantes et solutions

↳ **Commence ICI si tu es nouveau**

### 2. 📚 **README_WINDOWS_QUICKSTART.md**
**Guide détaillé pour Windows**

- Installation pysnmp 7.1.22 pas à pas
- Configuration .env
- Génération certificats SSL
- 3 terminaux détaillés
- Checklist complète

↳ **Référence principale**

### 3. 🐍 **PYSNMP_7_WINDOWS_GUIDE.md**
**Migration pysnmp 5.x → 7.x**

- Différences API principales
- Exemples de code GET/WALK/SET
- Configuration SNMPv3
- Erreurs courantes

↳ **Pour comprendre les changements**

### 4. 🧹 **test_windows.ps1**
**Script de test automatique PowerShell**

- Vérifie Python, Git, Docker
- Installe les dépendances
- Teste pysnmp 7.1.22
- Affiche les prochaines étapes

↳ **Lancer en Admin: `.\test_windows.ps1`**

### 5. 🗃 **collector/snmpv3_collector_v7.py**
**Collecteur SNMPv3 pour pysnmp 7.1.22**

Fonctionnalités:
- Mode TEST (OIDs basiques)
- Mode PRODUCTION (tables avancées)
- SNMPv3 avec authentification + chiffrement
- Async (asyncio natif)
- Logging complet
- JSON export des résultats

Usage:
```powershell
# Mode test
python collector/snmpv3_collector_v7.py --mode test --verbose

# Mode production
python collector/snmpv3_collector_v7.py --mode production --target 192.168.1.1 --user labuser
```

---

## ✅ Lancement Rapide

### Étape 1: Test Automatique (2 min)
```powershell
cd C:\snmp_project\Beta-SNMP
.\test_windows.ps1
```

### Étape 2: 3 Terminaux

**Terminal 1:** PostgreSQL
```powershell
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:15
```

**Terminal 2:** API
```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
cd "API + BDD"
python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem
```

**Terminal 3:** Collector
```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\Activate.ps1
python collector/snmpv3_collector_v7.py --mode test --verbose
```

### Étape 3: Vérifier
```powershell
curl -k https://localhost:8443/health
```

---

## 🐍 Changements PySnmp 5.x → 7.x

### Import
```python
# 5.x
from pysnmp.hlapi import *

# 7.x
from pysnmp import *
```

### SnmpEngine (OBLIGATOIRE en 7.x)
```python
# 5.x - optionnel
engine = SnmpEngine()  # généralement automatique

# 7.x - OBLIGATOIRE
engine = SnmpEngine()  # A PASSER PARTOUT
```

### UserIdentity (7.x nouveau)
```python
# 5.x
UsmUserData('user', 'auth_pass', 'priv_pass')

# 7.x - Constructeur en chaîne
user = UserIdentity('labuser')
user = user.with_authentication_protocol(AuthenticationProtocol.hmac_sha)
user = user.with_authentication_key('authpass')
user = user.with_privacy_protocol(PrivacyProtocol.aes)
user = user.with_privacy_key('privpass')
```

### Async (7.x natif)
```python
# 5.x - asyncore
iterator = getCmd(...)

# 7.x - asyncio
await engine.send(generator, target)
```

---

## 🛠 Architecture du Système

```
┌────────────────────────────────┐
│  Windows PowerShell - 3 Terminaux                    │
├────────────────────────────────┤
│                                                    │
│  [Terminal 1]        [Terminal 2]      [Terminal 3] │
│  PostgreSQL           API FastAPI       Collector    │
│  Port 5432            Port 8443          SNMPv3      │
│                                                    │
└────────────────────────────────┘
           ↘️            ↙️
        Docker         HTTPS:8443
        (Linux/Mac)      (GET,POST,etc)
                            ↑
        Collector SNMPv3 ▔▔▔▔▔▔▔▔▔▔▔ PostgreSQL
        pysnmp 7.1.22    Envoie données  Stockage
         (Async)          JSON
        ↓
    Switch/Routeur
    SNMPv3 Port 161
```

---

## 🛧 Troubleshooting Rapide

| Problème | Solution |
|---------|----------|
| `ModuleNotFoundError: pysnmp` | `pip install pysnmp==7.1.22 --force-reinstall` |
| "Port 8443 déjà utilisé" | `netstat -ano \| findstr :8443` puis `taskkill /PID` |
| "Certificate verify failed" | `pip install pyopenssl cryptography --upgrade` OU `curl -k ...` |
| PowerShell: "cannot be loaded" | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| "Timeout" SNMP | Ping le switch: `ping 192.168.1.1` et vérifier `.env` |

---

## 📄 Guides Complémentaires

1. **QUICKSTART_WINDOWS.md** → Démarrage (commence ici)
2. **README_WINDOWS_QUICKSTART.md** → Guide détaillé
3. **PYSNMP_7_WINDOWS_GUIDE.md** → Migration API
4. **collector/snmpv3_collector_v7.py** → Code source du collector

---

## 🌟 Points Clés

✅ **Entirement asynchrone** - Pas de blocage  
✅ **Production-ready** - Logging, gestion erreurs  
✅ **Async/await natif** - pysnmp 7.x + asyncio  
✅ **Windows-compatible** - PowerShell, paths Windows  
✅ **PostgreSQL** - Base de données persistante  
✅ **HTTPS** - API sécurisée avec certificats  
✅ **SNMPv3 complet** - Auth + Chiffrement  
✅ **JSON export** - Résultats exportés  

---

## 🚀 Prochaines Étapes

1. Lancer `test_windows.ps1` pour tout vérifier
2. Lire **QUICKSTART_WINDOWS.md** pour la config
3. Lancer les 3 terminaux
4. Tester avec `curl -k https://localhost:8443/health`
5. Accéder aux données SNMP

---

**🚀 Prêt? Lance le test: `.\test_windows.ps1`**
