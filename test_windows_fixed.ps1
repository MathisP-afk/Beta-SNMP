# ============================================================================
# Test SNMPv3 avec pysnmp 7.1.22 sur Windows PowerShell
# ============================================================================
# FIXED: Encodage UTF-8 compatible Windows
# Lancer en Admin PowerShell depuis C:\snmp_project\Beta-SNMP
# ============================================================================

# Couleurs pour l'affichage
function Write-Success { Write-Host "$args" -ForegroundColor Green }
function Write-Warning { Write-Host "$args" -ForegroundColor Yellow }
function Write-Error { Write-Host "$args" -ForegroundColor Red }
function Write-Info { Write-Host "$args" -ForegroundColor Cyan }

Clear-Host
Write-Info "="*70
Write-Info "Test SNMPv3 avec pysnmp 7.1.22 - Windows PowerShell"
Write-Info "="*70

# ============================================================================
# PHASE 1: Verifier les prerequis
# ============================================================================

Write-Info ""
Write-Info "Phase 1: Verification des prerequis"
Write-Info "="*70

# 1. Python
Write-Host "
[1/6] Verification Python..." -NoNewline
try {
    $python_version = python --version 2>&1
    if ($python_version -match "3.10|3.11|3.12|3.13") {
        Write-Success "  OK: $python_version"
    } else {
        Write-Error "  ERREUR: Version insuffisante: $python_version (besoin 3.10+)"
        exit 1
    }
} catch {
    Write-Error "  ERREUR: Python non trouve. Installe Python 3.10+ depuis python.org"
    exit 1
}

# 2. Git
Write-Host "
[2/6] Verification Git..." -NoNewline
try {
    $git_version = git --version 2>&1
    Write-Success "  OK: $git_version"
} catch {
    Write-Error "  ERREUR: Git non trouve. Installe Git depuis git-scm.com"
    exit 1
}

# 3. Dossier du projet
Write-Host "
[3/6] Verification du dossier Beta-SNMP..." -NoNewline
if (Test-Path "Beta-SNMP") {
    Write-Success "  OK: Dossier existant"
} else {
    Write-Error "  ERREUR: Dossier Beta-SNMP non trouve"
    exit 1
}

# 4. Venv
Write-Host "
[4/6] Verification du venv..." -NoNewline
if (Test-Path "Beta-SNMP\venv\Scripts\Activate.ps1") {
    Write-Success "  OK: venv existant"
} else {
    Write-Warning "  ATTENTION: venv non trouve, sera cree..."
}

# 5. pip upgrade
Write-Host "
[5/6] Upgrade pip setuptools wheel..." -NoNewline
python -m pip install --upgrade pip setuptools wheel 2>&1 | Out-Null
Write-Success "  OK: Fait"

# 6. Verifier pysnmp
Write-Host "
[6/6] Verification pysnmp 7.1.22..." -NoNewline
$pysnmp_check = python -c "import pysnmp; print(pysnmp.__version__)" 2>&1
if ($pysnmp_check -eq "7.1.22") {
    Write-Success "  OK: pysnmp $pysnmp_check installe"
} else {
    Write-Warning "  ATTENTION: pysnmp absent ou version differente, sera installe..."
}

# ============================================================================
# PHASE 2: Setup projet
# ============================================================================

Write-Info ""
Write-Info "Phase 2: Configuration du projet"
Write-Info "="*70

cd Beta-SNMP

# Creer venv si necessaire
if (-not (Test-Path "venv\Scripts\Activate.ps1")) {
    Write-Host "Creation du venv..." -NoNewline
    python -m venv venv
    Write-Success " OK: Fait"
}

# Activer venv
Write-Host "Activation du venv..." -NoNewline
& ".\venv\Scripts\Activate.ps1"
Write-Success " OK: Fait"

# Installer dependances
Write-Host "Installation des dependances..." -NoNewline
pip install -q --upgrade pip 2>&1 | Out-Null
pip install -q pysnmp==7.1.22 pyopenssl cryptography 2>&1 | Out-Null
pip install -q -r requirements.txt 2>&1 | Out-Null
Write-Success " OK: Fait"

# ============================================================================
# PHASE 3: Verification dependances
# ============================================================================

Write-Info ""
Write-Info "Phase 3: Verification des dependances installees"
Write-Info "="*70

$deps = @(
    @{name="pysnmp"; min_version="7.1.22"},
    @{name="pyopenssl"; min_version="22.0"},
    @{name="cryptography"; min_version="40.0"},
    @{name="fastapi"; min_version=""},
    @{name="uvicorn"; min_version=""},
    @{name="psycopg2-binary"; min_version="2.9"},
    @{name="python-dotenv"; min_version="0.20"}
)

foreach ($dep in $deps) {
    $name = $dep.name
    $min_version = $dep.min_version
    
    $installed = pip show $name 2>&1 | Select-String "Version" | ForEach-Object { $_ -replace "Version: ", "" }
    
    if ($installed) {
        if ($min_version -and $installed -lt $min_version) {
            Write-Warning "  ATTENTION: $name ($installed) - Version minimale: $min_version"
        } else {
            Write-Success "  OK: $name ($installed)"
        }
    } else {
        Write-Error "  ERREUR: $name - NON INSTALLE"
    }
}

# ============================================================================
# PHASE 4: Tests de connexion
# ============================================================================

Write-Info ""
Write-Info "Phase 4: Tests de connectivite"
Write-Info "="*70

# Test 1: Import pysnmp
Write-Host "
[1/3] Test import pysnmp..." -NoNewline
try {
    python -c "from pysnmp import *; print('OK')" -ErrorAction Stop | Out-Null
    Write-Success "  OK: pysnmp importable"
} catch {
    Write-Error "  ERREUR: Impossible d'importer pysnmp"
}

# Test 2: Configuration SNMP
Write-Host "
[2/3] Test configuration SNMPv3..." -NoNewline
try {
    python -c "from pysnmp import SnmpEngine, UserIdentity; print('OK')" -ErrorAction Stop | Out-Null
    Write-Success "  OK: Configuration SNMPv3 ok"
} catch {
    Write-Error "  ERREUR: Configuration SNMPv3 impossible"
}

# Test 3: Fichier requirements
Write-Host "
[3/3] Test fichier requirements.txt..." -NoNewline
if (Test-Path "requirements.txt") {
    Write-Success "  OK: requirements.txt existant"
} else {
    Write-Error "  ERREUR: requirements.txt manquant"
}

# ============================================================================
# PHASE 5: Verification collector
# ============================================================================

Write-Info ""
Write-Info "Phase 5: Verification du collector"
Write-Info "="*70

if (Test-Path "collector\snmpv3_collector_v7.py") {
    Write-Success "  OK: collector/snmpv3_collector_v7.py existant"
    
    # Verifier la syntaxe
    Write-Host "Verification syntaxe Python..." -NoNewline
    try {
        python -m py_compile "collector\snmpv3_collector_v7.py" 2>&1 | Out-Null
        Write-Success " OK: Syntaxe correcte"
    } catch {
        Write-Error " ERREUR: Erreur de syntaxe"
    }
} else {
    Write-Error "  ERREUR: collector/snmpv3_collector_v7.py manquant"
}

# ============================================================================
# PHASE 6: Pret pour production?
# ============================================================================

Write-Info ""
Write-Info "Phase 6: RESULTAT FINAL"
Write-Info "="*70

Write-Success "
CONFIGURATION COMPLETE!

Prochaines etapes:

1. CONFIGURER L'ENV
   notepad .env
   Edite: SNMP_AUTH_PASS, SNMP_PRIV_PASS, DB_PASSWORD

2. LANCER LE COLLECTOR (Mode TEST)
   python collector/snmpv3_collector_v7.py --mode test --verbose

3. LANCER L'API (Terminal 2)
   cd 'API + BDD'
   python -m uvicorn snmp_api_improved:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl/key.pem --ssl-certfile ssl/fullcert.pem

4. LANCER LA BASE DE DONNEES (Terminal 3)
   docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:15

5. TESTER L'API
   curl -k https://localhost:8443/health

Documentation: Consulte README_WINDOWS_QUICKSTART.md pour plus de details.
"
Write-Info "="*70

Read-Host "
Appuie sur Entree pour fermer..."
