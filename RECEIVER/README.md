# Collecteur SNMP Unifié

Collecteur SNMP hybride supportant SNMPv2c et SNMPv3, déployable via Docker. Il combine une capture passive (Scapy en mode promiscuous) et un polling actif SNMPv3, avec détection de menaces en temps réel et envoi vers l'API REST centrale.

---

## Programmes

### `snmp_collector_unified.py` — Collecteur principal

Script Python unique qui assure toute la chaîne de collecte SNMP. Il intègre :

- **Capture passive** : Scapy écoute en mode promiscuous sur l'interface réseau configurée et capture tout le trafic SNMP (v2c et v3) transitant sur le réseau.
- **Polling actif SNMPv3** : interrogation périodique du switch cible via SNMPv3 GET (pysnmp HLAPI). Récupère les informations système (`sysDescr`, `sysUpTime`, `sysName`...) et les compteurs d'interfaces (`ifInOctets`, `ifOutOctets`, `ifOperStatus`...).
- **Parsing BER/ASN.1** : décodage bas niveau des paquets SNMPv3 sans dépendance externe (TLV, OID, entiers, chaînes). Les paquets v2c sont parsés via la couche Scapy native.
- **Déchiffrement SNMPv3** : dérivation de clé SHA selon RFC 3414 + déchiffrement DES-CBC des PDU chiffrées, permettant de lire le contenu des paquets v3 capturés passivement.
- **Résolution OID** : bibliothèque intégrée de 34 OIDs courants (MIB-II système, interfaces, traps standards, Cisco, ressources hôte) traduits en noms lisibles.
- **Détection de menaces** : analyse de sévérité par scoring (NORMAL / SUSPECT / ELEVEE / CRITIQUE) basée sur le type PDU, les VarBinds, et le comportement dans le temps par IP source (flood, scan de communautés, brute-force auth v3, reconnaissance OID).
- **File d'attente thread-safe** : les paquets capturés sont mis en file (`SNMPPacketQueue`) puis envoyés par lot vers l'API REST par des workers parallèles.
- **Tracking par IP** : la classe `IPTracker` maintient un historique glissant par IP source (timestamps, communautés testées, échecs d'authentification, OIDs interrogés) pour la détection comportementale.

### `generate_alerts.py` — Générateur d'alertes de test

Script utilitaire qui envoie des requêtes SNMPv3 SET vers le switch pour simuler des alertes de sécurité (niveau CRITIQUE). Permet de valider la chaîne complète collecteur → API → interface web.

---

## Installation et déploiement Docker

### Prérequis

- Docker et Docker Compose installés.
- Accès réseau au switch SNMP (port 161) et à l'API REST (HTTPS).

### 1. Copier les fichiers sur la machine cible

```bash
scp Dockerfile docker-compose.yml requirements.txt snmp_collector_unified.py .env.example utilisateur@IP_MACHINE:/chemin/collecteur/
```

### 2. Configurer l'environnement

```bash
cd /chemin/collecteur
cp .env.example .env
nano .env
```

### Variables d'environnement

#### API REST

| Variable | Description | Obligatoire |
|---|---|---|
| `SNMP_API_URL` | URL de l'API centrale (ex: `https://api.exemple.fr`) | Oui |
| `SNMP_API_KEY` | Clé d'API Bearer pour l'authentification | Oui |

#### Capture réseau

| Variable | Description | Défaut |
|---|---|---|
| `SNMP_INTERFACE` | Interface réseau Linux (`ip a` pour vérifier) | `eth0` |
| `SNMP_WORKERS` | Nombre de workers d'envoi vers l'API | `3` |
| `SNMP_PORT` | Port SNMP à capturer | `162` |

#### SNMPv3 (polling actif + déchiffrement)

| Variable | Description | Obligatoire |
|---|---|---|
| `SNMP_SWITCH_IP` | IP du switch à interroger | Oui |
| `SNMP_V3_USERNAME` | Utilisateur SNMPv3 (USM) | Oui |
| `SNMP_V3_AUTH_PASSWORD` | Mot de passe d'authentification (SHA) | Oui |
| `SNMP_V3_PRIV_PASSWORD` | Mot de passe de chiffrement (DES) | Oui |
| `SNMP_V3_ENGINE_ID` | Engine ID du switch (hexadécimal) | Oui |
| `SNMP_POLL_INTERVAL` | Intervalle de polling en secondes | `60` |

#### Détection de menaces

| Variable | Description | Défaut |
|---|---|---|
| `SNMP_WHITELIST_IPS` | IPs autorisées (séparées par des virgules) | — |
| `SNMP_KNOWN_COMMUNITIES` | Community strings légitimes | `public,private` |
| `SNMP_KNOWN_V3_USERS` | Utilisateurs SNMPv3 légitimes | — |
| `SNMP_FLOOD_THRESHOLD` | Seuil de flood (requêtes/fenêtre) | `50` |
| `SNMP_FLOOD_CRITICAL` | Seuil de flood critique | `200` |
| `SNMP_FLOOD_WINDOW` | Fenêtre de détection flood (secondes) | `60` |
| `SNMP_BRUTEFORCE_THRESHOLD` | Seuil d'échecs auth avant alerte | `5` |
| `SNMP_BRUTEFORCE_WINDOW` | Fenêtre de détection brute-force (secondes) | `120` |

### 3. Résolution DNS (si nécessaire)

Si le nom de domaine de l'API n'est pas résolu par le DNS de la machine :

**Option A** — Ajouter au `/etc/hosts` de la machine hôte (hérité par le conteneur via `network_mode: host`) :

```bash
echo "10.0.0.5 api.exemple.fr" | sudo tee -a /etc/hosts
```

**Option B** — Utiliser `extra_hosts` dans `docker-compose.yml` :

```yaml
extra_hosts:
  - "api.exemple.fr:10.0.0.5"
```

### 4. Build et lancement

```bash
# Build de l'image
docker compose build

# Lancement en arrière-plan
docker compose up -d
```

### 5. Vérifier le bon fonctionnement

```bash
docker logs -f collecteur-snmp
```

Sortie attendue au démarrage :

```
[INIT] Collecteur SNMP Unifie v1.0 (v2c + v3)
[INIT] API: https://api.exemple.fr
[INIT] Scapy: OUI / Mode v3: OUI / Dechiffrement DES: OUI / Polling actif: OUI
[WORKER-0] Demarre
[WORKER-1] Demarre
[WORKER-2] Demarre
[SNIFFER] Demarrage capture passive (v2c + v3)...
[POLL] Polling actif v3 vers 10.0.0.1 (intervalle: 60s)
```

Le collecteur affiche périodiquement une ligne de statistiques :

```
[STATS] v2c:0 | v3:12 | Polls:5 | Q:0 | API OK:17 | API Fail:0 | Alertes:0
```

### Arrêt et suppression

```bash
# Arrêter le conteneur
docker compose down

# Rebuild après modification du code
docker compose up -d --build
```
