#!/usr/bin/env python3
"""
Test v2c - Génère du trafic SNMPv2c pour tester le collecteur unifié.
Envoie des GET/GETNEXT/SET v2c vers une cible (VM Linux par défaut).
Le trafic traverse le switch et est capturé par le SPAN.

Usage:
    python test_v2c.py                          # cible par défaut 10.204.0.182
    python test_v2c.py -t 10.204.0.182          # cible spécifique
    python test_v2c.py -t 10.204.0.182 -c public
"""

import asyncio
import argparse
import time

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    next_cmd,
    set_cmd,
)
from pysnmp.proto.rfc1902 import OctetString, Integer32


async def send_v2c_get(engine, community, target, oid):
    """Envoie un GET v2c."""
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        engine,
        CommunityData(community, mpModel=1),  # mpModel=1 = SNMPv2c
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    return errorIndication, errorStatus, varBinds


async def send_v2c_getnext(engine, community, target, oid):
    """Envoie un GETNEXT v2c."""
    errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
        engine,
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    return errorIndication, errorStatus, varBinds


async def send_v2c_set(engine, community, target, oid, value):
    """Envoie un SET v2c."""
    errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
        engine,
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid), value)
    )
    return errorIndication, errorStatus, varBinds


async def main(target_ip, community):
    engine = SnmpEngine()

    try:
        target = await UdpTransportTarget.create((target_ip, 161), timeout=3, retries=1)
    except (TypeError, AttributeError):
        target = UdpTransportTarget((target_ip, 161), timeout=3, retries=1)

    print(f"=== Test SNMPv2c vers {target_ip} (community: {community}) ===\n")

    # --- GET ---
    oids_get = [
        ('1.3.6.1.2.1.1.1.0', 'sysDescr'),
        ('1.3.6.1.2.1.1.3.0', 'sysUpTime'),
        ('1.3.6.1.2.1.1.5.0', 'sysName'),
        ('1.3.6.1.2.1.1.6.0', 'sysLocation'),
    ]

    for oid, name in oids_get:
        err, status, varbinds = await send_v2c_get(engine, community, target, oid)
        if err:
            print(f"  [GET] {name} ({oid}) -> ERREUR: {err}")
        elif status:
            print(f"  [GET] {name} ({oid}) -> STATUS: {status}")
        else:
            for o, v in varbinds:
                print(f"  [GET] {name} -> {v.prettyPrint()}")
        time.sleep(0.3)

    print()

    # --- GETNEXT ---
    oids_next = [
        ('1.3.6.1.2.1.1', 'system'),
        ('1.3.6.1.2.1.2.2.1.2', 'ifDescr'),
    ]

    for oid, name in oids_next:
        err, status, varbinds = await send_v2c_getnext(engine, community, target, oid)
        if err:
            print(f"  [GETNEXT] {name} ({oid}) -> ERREUR: {err}")
        elif status:
            print(f"  [GETNEXT] {name} ({oid}) -> STATUS: {status}")
        else:
            for o, v in varbinds:
                print(f"  [GETNEXT] {name} -> {o.prettyPrint()} = {v.prettyPrint()}")
        time.sleep(0.3)

    print()

    # --- SET (avec community "private", peut échouer si pas configuré) ---
    print("  [SET] sysLocation -> 'Salle_TP_RT3_Test_V2C'")
    err, status, varbinds = await send_v2c_set(
        engine, community, target,
        '1.3.6.1.2.1.1.6.0', OctetString('Salle_TP_RT3_Test_V2C')
    )
    if err:
        print(f"    -> ERREUR: {err}")
    elif status:
        print(f"    -> STATUS erreur: {status} (normal si community read-only)")
    else:
        for o, v in varbinds:
            print(f"    -> OK: {v.prettyPrint()}")

    print(f"\n=== Terminé ! Vérifiez le collecteur unifié pour les paquets v2c ===")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Générateur de trafic SNMPv2c')
    parser.add_argument('-t', '--target', default='10.204.0.182',
                        help='IP cible (défaut: 10.204.0.182 = VM Linux)')
    parser.add_argument('-c', '--community', default='public',
                        help='Community string (défaut: public)')
    args = parser.parse_args()

    asyncio.run(main(args.target, args.community))
