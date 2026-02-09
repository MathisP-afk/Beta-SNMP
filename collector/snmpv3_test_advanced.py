#!/usr/bin/env python3
"""
SNMPv3 Test Avance - Force SHA auth + DES priv
Script de test direct pour debug SNMPv3
"""

import asyncio
import sys
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
)


async def test_snmp(host, port, username, auth_pass, priv_pass):
    print(f"\nTest SNMPv3:")
    print(f"  Host: {host}:{port}")
    print(f"  Username: {username}")
    print(f"  Auth: SHA, Priv: DES")
    print(f"  Timeout: 10s")
    print()
    
    snmp_engine = SnmpEngine()
    
    try:
        # Creer l'utilisateur avec SHA + DES explicitement
        user_data = UsmUserData(
            userName=username,
            authKey=auth_pass,
            authProtocol=usmHMACSHAAuthProtocol,
            privKey=priv_pass,
            privProtocol=usmDESPrivProtocol,
        )
        
        print("[*] UsmUserData cree (SHA+DES)...")
        
        # Target avec timeout plus long pour debug
        target = await UdpTransportTarget.create(
            (host, port),
            timeout=10,  # 10 secondes pour debug
            retries=1,
        )
        
        print("[*] Target UDP cree...")
        
        context = ContextData()
        
        print("[*] Envoi GET sysDescr...")
        
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            user_data,
            target,
            context,
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
        )
        
        if errorIndication:
            print(f"[!] ERREUR: {errorIndication}")
            return False
        
        if errorStatus:
            print(f"[!] STATUS ERROR: {errorStatus.prettyPrint()}")
            return False
        
        print("[+] REPONSE RECUE!")
        for varBind in varBinds:
            oid, value = varBind
            print(f"    {oid} = {value}")
        
        return True
    
    except Exception as e:
        print(f"[!] EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        snmp_engine.close_dispatcher()


async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SNMPv3 Advanced Test")
    parser.add_argument("--host", default="192.168.1.39")
    parser.add_argument("--port", type=int, default=161)
    parser.add_argument("--username", default="Alleria_W")
    parser.add_argument("--auth-pass", default="Vereesa_W")
    parser.add_argument("--priv-pass", default="Windrunner")
    
    args = parser.parse_args()
    
    success = await test_snmp(
        args.host,
        args.port,
        args.username,
        args.auth_pass,
        args.priv_pass,
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
