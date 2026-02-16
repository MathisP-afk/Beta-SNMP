#!/usr/bin/env python3
"""
Script de diagnostic SNMPv3 :
  1. Découvre l'Engine ID du switch
  2. Envoie un trap de test vers le récepteur local
"""

import asyncio
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd, send_notification,
    CommunityData, NotificationType,
)
from pysnmp.entity import config


AUTH_SHA = config.USM_AUTH_HMAC96_SHA
PRIV_DES = config.USM_PRIV_CBC56_DES

# --- Config (à adapter) ---
SWITCH_IP = "10.204.0.119"
USERNAME = "Alleria_W"
AUTH_PASS = "Vereesa_W"
PRIV_PASS = "Windrunner"
RECEIVER_IP = "127.0.0.1"
RECEIVER_PORT = 162


async def discover_engine_id():
    """Étape 1 : GET sysDescr sur le switch pour découvrir l'Engine ID."""
    print(f"\n{'='*60}")
    print(f"[1] Découverte Engine ID - GET sysDescr vers {SWITCH_IP}:161")
    print(f"{'='*60}")

    snmp_engine = SnmpEngine()

    try:
        target = await UdpTransportTarget.create(
            (SWITCH_IP, 161), timeout=5, retries=2
        )
    except (TypeError, AttributeError):
        target = UdpTransportTarget((SWITCH_IP, 161), timeout=5, retries=2)

    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        snmp_engine,
        UsmUserData(
            USERNAME, AUTH_PASS, PRIV_PASS,
            authProtocol=AUTH_SHA, privProtocol=PRIV_DES
        ),
        target,
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),  # sysName
    )

    if errorIndication:
        print(f"[ERREUR] {errorIndication}")
        return None

    if errorStatus:
        print(f"[ERREUR SNMP] {errorStatus.prettyPrint()} à {errorIndex}")
        return None

    print("[OK] Réponse reçue du switch :")
    for oid, val in varBinds:
        print(f"  {oid.prettyPrint()} = {val.prettyPrint()}")

    # Extraire l'Engine ID depuis le cache interne du moteur SNMP
    engine_id = None

    # Méthode 1 : LCD (Local Configuration Datastore)
    try:
        lcd = snmp_engine.get_user_name(snmp_engine.snmp_engine_id)
        print(f"\n[INFO] Engine ID local: {snmp_engine.snmp_engine_id.prettyPrint()}")
    except Exception:
        pass

    # Méthode 2 : parcourir le cache du transport
    try:
        mib_builder = snmp_engine.get_mib_builder()
        print(f"[INFO] MIB builder accessible")
    except Exception:
        pass

    # Méthode 3 : accès direct au cache USM
    try:
        usm_table = snmp_engine.message_dispatcher._cache
        print(f"[INFO] Cache dispatcher: {type(usm_table)}")
        if hasattr(usm_table, 'items'):
            for k, v in list(usm_table.items())[:5]:
                print(f"  Cache entry: {k} -> {type(v)}")
    except Exception as e:
        print(f"[INFO] Cache non accessible: {e}")

    # Méthode 4 : essayer les attributs pysnmp 7.x
    try:
        for attr_name in dir(snmp_engine):
            if 'engine' in attr_name.lower() and 'id' in attr_name.lower():
                val = getattr(snmp_engine, attr_name)
                if callable(val):
                    continue
                print(f"  snmpEngine.{attr_name} = {val}")
                if hasattr(val, 'prettyPrint'):
                    hex_val = bytes(val).hex()
                    print(f"  -> hex: {hex_val}")
                    engine_id = hex_val
    except Exception as e:
        print(f"[INFO] Scan attributs: {e}")

    return engine_id


async def send_test_trap():
    """Étape 2 : Envoie un trap linkUp de test vers le récepteur local."""
    print(f"\n{'='*60}")
    print(f"[2] Envoi d'un trap de test vers {RECEIVER_IP}:{RECEIVER_PORT}")
    print(f"{'='*60}")

    snmp_engine = SnmpEngine()

    try:
        target = await UdpTransportTarget.create(
            (RECEIVER_IP, RECEIVER_PORT), timeout=5, retries=0
        )
    except (TypeError, AttributeError):
        target = UdpTransportTarget((RECEIVER_IP, RECEIVER_PORT), timeout=5, retries=0)

    errorIndication, errorStatus, errorIndex, varBinds = await send_notification(
        snmp_engine,
        UsmUserData(
            USERNAME, AUTH_PASS, PRIV_PASS,
            authProtocol=AUTH_SHA, privProtocol=PRIV_DES
        ),
        target,
        ContextData(),
        'trap',
        NotificationType(
            ObjectIdentity('1.3.6.1.6.3.1.1.5.4')  # linkUp
        ).add_varbinds(
            ObjectType(
                ObjectIdentity('1.3.6.1.2.1.2.2.1.7.1'),  # ifAdminStatus.1
                1  # UP
            )
        )
    )

    if errorIndication:
        print(f"[ERREUR] {errorIndication}")
    else:
        print("[OK] Trap linkUp envoyé !")


async def main():
    print("=== Diagnostic SNMPv3 ===\n")

    engine_id = await discover_engine_id()

    if engine_id:
        print(f"\n>>> ENGINE ID DU SWITCH: {engine_id}")
        print(f">>> Utilise: --engine-id {engine_id}")

    await send_test_trap()

    print(f"\n{'='*60}")
    print("Terminé. Si le récepteur tourne, tu devrais voir le trap.")
    print(f"{'='*60}")


if __name__ == '__main__':
    asyncio.run(main())
