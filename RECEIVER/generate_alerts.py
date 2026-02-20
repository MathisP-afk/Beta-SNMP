#!/usr/bin/env python3
"""
Générateur d'alertes SNMP aléatoires pour tests.
Envoie des paquets v2c et v3 avec alerte_securite à l'API.

Usage:
    python generate_alerts.py
    python generate_alerts.py --count 20 --interval 5
"""

import argparse
import random
import datetime
import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_URL = "https://api.sae.botturi.fr"
API_KEY = "GDT98WBtTizrMUQcxEGD1Aw7YNzGL0qiywklUfD2i4PRNng4LWE018jYjrOCgKCm"

# --- Données aléatoires ---

FAKE_IPS = [
    "10.204.0.50", "10.204.0.51", "10.204.0.100", "10.204.0.119",
    "192.168.1.10", "192.168.1.254", "172.16.0.1", "10.0.0.66",
]

ALERT_SCENARIOS = [
    {
        "type_pdu": "SetRequest",
        "niveau": "CRITIQUE",
        "oid": "1.3.6.1.2.1.2.2.1.7.3",
        "oid_name": "ifAdminStatus",
        "oid_desc": "Statut Admin (1=UP, 2=DOWN)",
        "value": "2",
        "message": "Tentative de désactivation d'interface",
    },
    {
        "type_pdu": "Trap",
        "niveau": "CRITIQUE",
        "oid": "1.3.6.1.6.3.1.1.5.5",
        "oid_name": "authenticationFailure",
        "oid_desc": "Échec d'authentification",
        "value": "",
        "message": "Échec d'authentification SNMP détecté",
    },
    {
        "type_pdu": "SetRequest",
        "niveau": "ELEVEE",
        "oid": "1.3.6.1.2.1.1.6.0",
        "oid_name": "sysLocation",
        "oid_desc": "Emplacement physique",
        "value": "HACKED",
        "message": "Modification suspecte de sysLocation",
    },
    {
        "type_pdu": "SetRequest",
        "niveau": "CRITIQUE",
        "oid": "1.3.6.1.2.1.1.5.0",
        "oid_name": "sysName",
        "oid_desc": "Nom du système",
        "value": "ROGUE-SWITCH",
        "message": "Modification suspecte du nom système",
    },
    {
        "type_pdu": "Trap",
        "niveau": "ELEVEE",
        "oid": "1.3.6.1.6.3.1.1.5.3",
        "oid_name": "linkDown",
        "oid_desc": "Interface désactivée",
        "value": "",
        "message": "Interface réseau tombée",
    },
    {
        "type_pdu": "GetRequest",
        "niveau": "ELEVEE",
        "oid": "1.3.6.1.2.1.2.2.1.7." + "9" * 130,
        "oid_name": "Unknown_OID",
        "oid_desc": "OID anormalement long (possible buffer overflow)",
        "value": "NULL",
        "message": "OID suspect de taille anormale",
    },
    {
        "type_pdu": "SetRequest",
        "niveau": "CRITIQUE",
        "oid": "1.3.6.1.2.1.2.2.1.7.1",
        "oid_name": "ifAdminStatus",
        "oid_desc": "Statut Admin (1=UP, 2=DOWN)",
        "value": "2",
        "message": "Shutdown de port détecté via SetRequest",
    },
    {
        "type_pdu": "Trap",
        "niveau": "CRITIQUE",
        "oid": "1.3.6.1.4.1.9.9.43.2.0.1",
        "oid_name": "ciscoConfigManEvent",
        "oid_desc": "Événement config Cisco",
        "value": "",
        "message": "Modification de configuration Cisco détectée",
    },
]

V3_USERS = ["Alleria_W", "admin_snmp", "monitor_v3", "intrus_inconnu"]

# Scénario spam : même IP, communautés variées (simule brute-force communauté)
SPAM_IP = "10.0.0.66"
SPAM_COMMUNITIES = [
    "public", "private", "secret", "admin", "test",
    "community1", "snmp_rw", "monitor", "backup", "cisco",
]


def generate_spam_v2c_alert():
    """Génère un paquet de spam/brute-force communauté depuis une même IP."""
    now = datetime.datetime.now().isoformat()
    community = random.choice(SPAM_COMMUNITIES)
    oid = random.choice([
        "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.2.1.0",
    ])
    return {
        "source_ip": SPAM_IP,
        "source_port": random.randint(1024, 65535),
        "dest_ip": "10.204.0.119",
        "dest_port": 161,
        "community": community,
        "oid_racine": oid,
        "type_pdu": "GetRequest",
        "request_id": random.randint(1, 999999),
        "error_status": "0",
        "error_index": 0,
        "contenu": {
            "varbinds": [
                {
                    "oid": oid,
                    "oid_name": "sysDescr",
                    "oid_desc": "Description du système",
                    "value": "NULL",
                    "type": "test_spam",
                }
            ],
            "dico_valeurs": {oid: "NULL"},
            "capture_mode": "test",
            "alerte_securite": {
                "niveau": "ELEVEE",
                "message": f"Spam/brute-force communauté depuis {SPAM_IP} "
                           f"(community={community})",
                "timestamp": now,
                "details": "PDU: GetRequest — scan de communautés",
                "action_requise": f"Vérifier {SPAM_IP}",
            },
        },
    }


def generate_v2c_alert():
    scenario = random.choice(ALERT_SCENARIOS)
    src_ip = random.choice(FAKE_IPS)
    dst_ip = random.choice(FAKE_IPS)
    now = datetime.datetime.now().isoformat()

    return {
        "source_ip": src_ip,
        "source_port": random.randint(1024, 65535),
        "dest_ip": dst_ip,
        "dest_port": random.choice([161, 162]),
        "community": random.choice(["public", "private", "secret_community"]),
        "oid_racine": scenario["oid"],
        "type_pdu": scenario["type_pdu"],
        "request_id": random.randint(1, 999999),
        "error_status": "0",
        "error_index": 0,
        "contenu": {
            "varbinds": [
                {
                    "oid": scenario["oid"],
                    "oid_name": scenario["oid_name"],
                    "oid_desc": scenario["oid_desc"],
                    "value": scenario["value"],
                    "type": "test_alert",
                }
            ],
            "dico_valeurs": {scenario["oid"]: scenario["value"]},
            "capture_mode": "test",
            "alerte_securite": {
                "niveau": scenario["niveau"],
                "message": f"{scenario['message']} ({src_ip} -> {dst_ip})",
                "timestamp": now,
                "details": f"PDU: {scenario['type_pdu']}",
                "action_requise": f"Vérifier {src_ip}",
            },
        },
    }


def generate_v3_alert():
    scenario = random.choice(ALERT_SCENARIOS)
    src_ip = random.choice(FAKE_IPS)
    dst_ip = random.choice(FAKE_IPS)
    now = datetime.datetime.now().isoformat()

    return {
        "source_ip": src_ip,
        "source_port": random.randint(1024, 65535),
        "dest_ip": dst_ip,
        "dest_port": random.choice([161, 162]),
        "oid_racine": scenario["oid"],
        "type_pdu": scenario["type_pdu"],
        "contexte": "",
        "niveau_securite": random.choice(["authPriv", "authNoPriv"]),
        "utilisateur": random.choice(V3_USERS),
        "request_id": random.randint(1, 999999),
        "error_status": "0",
        "error_index": 0,
        "engine_id": "80004fb8054d534917e0c200",
        "msg_id": random.randint(1, 999999),
        "contenu": {
            "varbinds": [
                {
                    "oid": scenario["oid"],
                    "oid_name": scenario["oid_name"],
                    "oid_desc": scenario["oid_desc"],
                    "value": scenario["value"],
                    "type": "test_alert",
                }
            ],
            "dico_valeurs": {scenario["oid"]: scenario["value"]},
            "capture_mode": "test",
            "decrypted": True,
            "alerte_securite": {
                "niveau": scenario["niveau"],
                "message": f"{scenario['message']} ({src_ip} -> {dst_ip})",
                "timestamp": now,
                "details": f"PDU: {scenario['type_pdu']}",
                "action_requise": f"Vérifier {src_ip}",
            },
        },
    }


def send_alert(session, alert, version):
    if version == "v2c":
        url = f"{API_URL}/snmp/v2c/add"
    else:
        url = f"{API_URL}/snmp/v3/add"

    resp = session.post(url, json=alert, timeout=5)
    return resp.status_code, resp.text


def main():
    parser = argparse.ArgumentParser(description="Générateur d'alertes SNMP pour tests")
    parser.add_argument("-c", "--count", type=int, default=10,
                        help="Nombre d'alertes à générer (défaut: 10)")
    parser.add_argument("-i", "--interval", type=float, default=2,
                        help="Intervalle entre chaque alerte en secondes (défaut: 2)")
    parser.add_argument("--v2c-only", action="store_true",
                        help="Générer uniquement des alertes v2c")
    parser.add_argument("--v3-only", action="store_true",
                        help="Générer uniquement des alertes v3")
    parser.add_argument("--spam", action="store_true",
                        help="Inclure des alertes de spam/brute-force communauté")
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    })
    session.verify = False

    print(f"=== Générateur d'alertes SNMP ===")
    print(f"API: {API_URL}")
    print(f"Alertes à envoyer: {args.count}")
    print(f"Intervalle: {args.interval}s")
    print(f"================================\n")

    ok = 0
    fail = 0

    for i in range(1, args.count + 1):
        if args.spam and random.random() < 0.3:
            version = "v2c"
            alert = generate_spam_v2c_alert()
        elif args.v2c_only:
            version = "v2c"
            alert = generate_v2c_alert()
        elif args.v3_only:
            version = "v3"
            alert = generate_v3_alert()
        else:
            version = random.choice(["v2c", "v3"])
            if version == "v2c":
                alert = generate_v2c_alert()
            else:
                alert = generate_v3_alert()

        niveau = alert["contenu"]["alerte_securite"]["niveau"]
        msg = alert["contenu"]["alerte_securite"]["message"]

        try:
            status, body = send_alert(session, alert, version)
            if status in [200, 201]:
                ok += 1
                print(f"[{i}/{args.count}] OK  {version} | {niveau} | {alert['type_pdu']} | {msg}")
            else:
                fail += 1
                print(f"[{i}/{args.count}] FAIL {version} | HTTP {status} | {body[:100]}")
        except Exception as e:
            fail += 1
            print(f"[{i}/{args.count}] ERR  {version} | {e}")

        if i < args.count:
            time.sleep(args.interval)

    print(f"\n=== Terminé : {ok} envoyées, {fail} échouées ===")


if __name__ == "__main__":
    main()
