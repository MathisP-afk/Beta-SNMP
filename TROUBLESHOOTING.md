# 🔧 TROUBLESHOOTING - Problèmes Courants

## ❌ PowerShell: "n'est pas reconnu" / Activation venv échoue

**Problème:**
```powershell
.\venv\Scripts\Activate.ps1 : Le terme «.\venv\Scripts\Activate.ps1» n'est pas reconnu
```

**Solution 1: Changer la Execution Policy (RECOMMANDÉ)**
```powershell
# En tant qu'Admin PowerShell:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Vérifier:
Get-ExecutionPolicy
# Résultat: RemoteSigned

# Puis activation:
.\venv\Scripts\Activate.ps1
# Prompt: (venv) PS C:\snmp_project\Beta-SNMP>
```

**Solution 2: Utiliser CMD.exe à la place**
```cmd
REM Depuis CMD (pas PowerShell):
cd C:\snmp_project\Beta-SNMP
venv\Scripts\activate.bat
REM Prompt: (venv) C:\snmp_project\Beta-SNMP>
```

**Solution 3: Utiliser Python directement**
```powershell
# Sans activer venv, juste lancer avec python complet:
C:\snmp_project\Beta-SNMP\venv\Scripts\python.exe collector/snmpv3_collector.py --mode test
```

---

## ❌ SNMP Timeout: "No SNMP response received before timeout"

**Problème:**
```
2026-02-08 17:30:38,270 - WARNING - SNMP Error: No SNMP response received before timeout
ERREUR: Impossible de recuperer sysDescr
```

**Cause:** Il n'y a **PAS d'agent SNMP** qui écoute sur `127.0.0.1:161`

**Solution 1: Lancer un Mock SNMP Agent (RECOMMANDÉ pour TEST)**

Crée `collector/mock_snmp_agent.py` :

```python
#!/usr/bin/env python3
"""
Mock SNMP Agent - SNMPv3
Simule un device SNMP pour tester le collector localement
"""

import sys
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmtManager, context
from pysnmp.carrier.asynsock import dgram
from pysnmp import debug

# Créer l'engine SNMP
snmpEngine = engine.SnmpEngine()

# Configuration UDP transport
transport = dgram.UdpTransport()
transport.openServerMode(('127.0.0.1', 161))
snmpEngine.transportDispatcher.registerTransport(dgram.UdpTransport.supportedDomains[0], transport)

# Ajouter l'utilisateur SNMPv3
config.addV3User(
    snmpEngine,
    'admin',
    config.usmHMACMD5AuthProtocol, 'authPassword123',
    config.usmDESPrivProtocol, 'privPassword123'
)

# Ajouter les MIB objects
config.addVacmUser(
    snmpEngine, 3, 'admin', 'authPriv',
    (1, 3, 6, 1, 2, 1, 1),  # system group
    (1, 3, 6, 1, 2, 1, 1),
    contextName=''
)

# Backend for cmtManager
snmpContext = context.SnmpContext(snmpEngine)
cbCtx = cmtManager.NotificationReceiver(snmpEngine, snmpContext)

snmpEngine.observer.registerObserver(
    cbCtx, 'rfc3412.receiveMessage:request',
    cbCtx, 'rfc3412.receiveMessage:request'
)

# Données simulées
VARBINDS = {
    '1.3.6.1.2.1.1.1.0': 'Cisco IOS XE Software - Mock Device',
    '1.3.6.1.2.1.1.3.0': '123456789',
    '1.3.6.1.2.1.1.5.0': 'MockSwitch',
    '1.3.6.1.2.1.1.6.0': 'Arles, France',
}

print("🎭 Mock SNMP Agent - SNMPv3 Started")
print(f"   Listening on: 127.0.0.1:161")
print(f"   Username: admin")
print(f"   Auth Pass: authPassword123")
print(f"   Priv Pass: privPassword123")
print()
print("Data simulées:")
for oid, value in VARBINDS.items():
    print(f"  {oid} = {value}")
print()
print("Ctrl+C pour arrêter\n")

try:
    snmpEngine.transportDispatcher.jobStarted(1)
    snmpEngine.transportDispatcher.runDispatcher()
except KeyboardInterrupt:
    print("\n👋 Agent arrêté")
    sys.exit(0)
```

**Puis lancer en 2 terminaux:**

**Terminal 1: Mock Agent**
```powershell
cd C:\snmp_project\Beta-SNMP
.\ venv\Scripts\python.exe collector/mock_snmp_agent.py
# Résultat: "Mock SNMP Agent - SNMPv3 Started"
```

**Terminal 2: Collector**
```powershell
cd C:\snmp_project\Beta-SNMP
.\venv\Scripts\python.exe collector/snmpv3_collector.py --mode test --verbose
# Résultat: OK - OIDs collectés
```

---

**Solution 2: Utiliser un Device SNMP réel**

Si tu as un switch/routeur SNMP réel:

```powershell
python collector/snmpv3_collector.py --mode production \
  --host 192.168.1.1 \
  --username admin \
  --auth-pass monAuthPass \
  --priv-pass monPrivPass \
  --verbose
```

---

## ✅ Checklist Fixes

- [ ] `Get-ExecutionPolicy` retourne `RemoteSigned`
- [ ] Prompt commence par `(venv)`
- [ ] Mock agent tourne sur Terminal 1
- [ ] Collector retourne des OIDs sur Terminal 2
- [ ] Pas de timeouts

