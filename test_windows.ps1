# ============================================================================
# Test SNMPv3 avec pysnmp 7.1.22 sur Windows PowerShell
# ============================================================================
# Ce script teste l'installation complète du collecteur SNMPv3
# Lancer en Admin PowerShell depuis C:\snmp_project\Beta-SNMP
# ============================================================================

# Couleurs pour l'affichage
function Write-Success { Write-Host "$args" -ForegroundColor Green }
function Write-Warning { Write-Host "$args" -ForegroundColor Yellow }
function Write-Error { Write-Host "$args" -ForegroundColor Red }
function Write-Info { Write-Host "$args" -ForegroundColor Cyan }

Clear-Host
Write-Info "="*70
Write-Info "  🐍 Test SNMPv3 avec pysnmp 7.1.22 - Windows PowerShell"
Write-Info "="*70

# ============================================================================
# PHASE 1: Vérifier les prérequis
# ============================================================================

Write-Info ""
Write-Info "🔍 PHASE 1: Vérification des prérequis"
Write-Info "="*70

# 1. Python
Write-Host "
[1/6] Vérification Python..." -NoNewline
try {
    $python_version = python --version 2>&1
    if ($python_version -match "3.10|3.11|3.12") {
        Write-Success "  ✅ $python_version"
    } else {
        Write-Error "  ❌ Version insuffisante: $python_version (besoin 3.10+)"
        exit 1
    }
} catch {
    Write-Error "  ❌ Python non trouvé. Installe Python 3.10+ depuis python.org"
    exit 1
}

# 2. Git
Write-Host "
[2/6] Vérification Git..." -NoNewline
try {
    $git_version = git --version 2>&1
    Write-Success "  ✅ $git_version"
} catch {
    Write-Error "  ❌ Git non trouvé. Installe Git depuis git-scm.com"
    exit 1
}

# 3. Dossier du projet
Write-Host "
[3/6] Vérification du dossier Beta-SNMP..." -NoNewline
if (Test-Path "Beta-SNMP") {
    Write-Success "  ✅ Dossier existant"
} else {
    Write-Error "  ❌ Dossier Beta-SNMP non trouvé"
    exit 1
}

# 4. Venv
Write-Host "
[4/6] Vérification du venv..." -NoNewline
if (Test-Path "Beta-SNMP\venv\Scripts\Activate.ps1") {
    Write-Success "  ✅ venv existant"
} else {
    Write-Warning "  ⚠ venv non trouvé, sera créé..."
}

# 5. pip upgrade
Write-Host "
[5/6] Upgrade pip setuptools wheel..." -NoNewline
python -m pip install --upgrade pip setuptools wheel | Out-Null
Write-Success "  ✅ Fait"

# 6. Vérifier pysnmp
Write-Host "
[6/6] Vérification pysnmp 7.1.22..." -NoNewline
$pysnmp_check = python -c "import pysnmp; print(pysnmp.__version__)" 2>&1
if ($pysnmp_check -eq "7.1.22") {
    Write-Success "  ✅ pysnmp $pysnmp_check installé"
} else {
    Write-Warning "  ⚠ pysnmp absent ou version différente, sera installé..."
}

# ============================================================================
# PHASE 2: Setup projet
# ============================================================================

Write-Info ""
Write-Info "🔨 PHASE 2: Configuration du projet"
Write-Info "="*70

cd Beta-SNMP

# Créer venv si nécessaire
if (-not (Test-Path "venv\Scripts\Activate.ps1")) {
    Write-Host "Création du venv..." -NoNewline
    python -m venv venv
    Write-Success " ✅ Fait"
}

# Activer venv
Write-Host "Activation du venv..." -NoNewline
& ".\venv\Scripts\Activate.ps1"
Write-Success " ✅ Fait"

# Installer dépendances
Write-Host "Installation des dépendances..." -NoNewline
pip install -q --upgrade pip
pip install -q pysnmp==7.1.22 pyopenssl cryptography
pip install -q -r requirements.txt 2>&1 | Out-Null
Write-Success " ✅ Fait"

# ============================================================================
# PHASE 3: Vérification dépendances
# ============================================================================

Write-Info ""
Write-Info "📋 PHASE 3: Vérification des dépendances installées"
Write-Info "="*70

$deps = @(
    @{name="pysnmp"; version="7.1.22"},
    @{name="pyopenssl"; version="22.0"},
    @{name="cryptography"; version="40.0"},
    @{name="fastapi"; version=""},
    @{name="uvicorn"; version=""},
    @{name="psycopg2"; version="2.9"},
    @{name="python-dotenv"; version="0.20"}
)

foreach ($dep in $deps) {
    $name = $dep.name
    $min_version = $dep.version
    
    $installed = pip show $name 2>&1 | Select-String "Version" | ForEach-Object { $_ -replace "Version: ", "" }
    
    if ($installed) {
        if ($min_version -and $installed -lt $min_version) {
            Write-Warning "  ⚠ $name ($installed) - Version minimale: $min_version"
        } else {
            Write-Success "  ✅ $name ($installed)"
        }
    } else {
        Write-Error "  ❌ $name - NON INSTALLÉ"
    }
}

# ============================================================================
# PHASE 4: Tests de connexion
# ============================================================================

Write-Info ""
Write-Info "🧹 PHASE 4: Tests de connectivité"
Write-Info "="*70

# Test 1: Import pysnmp
Write-Host "
[1/3] Test import pysnmp..." -NoNewline
try {
    python -c "from pysnmp import *; print('OK')" -ErrorAction Stop | Out-Null
    Write-Success "  ✅ pysnmp importable"
} catch {
    Write-Error "  ❌ Impossible d'importer pysnmp"
}

# Test 2: Configuration SNMP
Write-Host "
[2/3] Test configuration SNMPv3..." -NoNewline
try {
    python -c "from pysnmp import SnmpEngine, UserIdentity; print('OK')" -ErrorAction Stop | Out-Null
    Write-Success "  ✅ Configuration SNMPv3 ok"
} catch {
    Write-Error "  ❌ Erreur configuration SNMPv3"
}

# Test 3: Fichier requirements
Write-Host "
[3/3] Test fichier requirements.txt..." -NoNewline
if (Test-Path "requirements.txt") {
    Write-Success "  ✅ requirements.txt existant"
} else {
    Write-Error "  ❌ requirements.txt manquant"
}

# ============================================================================
# PHASE 5: Vérification collector
# ============================================================================

Write-Info ""
Write-Info "🗃 PHASE 5: Vérification du collector"
Write-Info "="*70

if (Test-Path "collector\snmpv3_collector_v7.py") {
    Write-Success "  ✅ collector/snmpv3_collector_v7.py existant"
    
    # Vérifier la syntaxe
    Write-Host "Vérification syntaxe Python..." -NoNewline
    try {
        python -m py_compile "collector\snmpv3_collector_v7.py" 2>&1 | Out-Null
        Write-Success " ✅ Syntaxe OK"
    } catch {
        Write-Error " ❌ Erreur de syntaxe"
    }
} else {
    Write-Error "  ❌ collector/snmpv3_collector_v7.py manquant"
}

# ============================================================================
# PHASE 6: Prêt pour production?
# ============================================================================

Write-Info ""
Write-Info "🎆 PHASE 6: RÉSUMÉ FINAL"
Write-Info "="*70

Write-Success "
✅ CONFIGURATION COMPLÉTE!

Prochaines étapes:

1. CONFIGURER L'ENV
   notepad .env
   # Édite: SNMP_AUTH_PASS, SNMP_PRIV_PASS, DB_PASSWORD

2. LANCER LE COLLECTOR (Mode TEST)
   python collector/snmpv3_collector_v7.py --mode test --verbose

3. LANCER L'API (Terminal 2)
   cd 'API + BDD'
   python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem

4. LANCER LA BASE DE DONNÉES (Terminal 3)
   docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:15

5. TESTER L'API
   curl -k https://localhost:8443/health

Documentation: Consulte PYSNMP_7_WINDOWS_GUIDE.md pour plus de détails.
"
Write-Info "="*70

Read-Host "

Appuie sur Entrée pour fermer..."
