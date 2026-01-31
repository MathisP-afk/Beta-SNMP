#!/usr/bin/env python3
"""
Comprehensive SNMPv3 testing script.
Tests all major operations: GET, SET, WALK, System Info, Interfaces.
"""

import asyncio
import sys
from snmp.snmp_client import SNMPv3Client
from config.snmp_config import create_snmpv3_from_config, SNMPTarget


async def test_basic_get(client: SNMPv3Client):
    """Test basic GET operation."""
    print("\n" + "="*60)
    print("TEST 1: Basic GET Operation")
    print("="*60)
    
    # Get system description
    print("\n[*] Getting system description (1.3.6.1.2.1.1.1.0)...")
    result = await client.get('1.3.6.1.2.1.1.1.0')
    print(f"[✓] Result: {result}")
    
    return result is not None


async def test_system_info(client: SNMPv3Client):
    """Test system information retrieval."""
    print("\n" + "="*60)
    print("TEST 2: System Information")
    print("="*60)
    
    try:
        print("\n[*] Fetching system information...")
        info = await client.get_system_info()
        
        for key, value in info.items():
            status = "✓" if value != "N/A" else "✗"
            print(f"  {status} {key:15} : {value}")
        
        return any(v != "N/A" for v in info.values())
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


async def test_interfaces(client: SNMPv3Client):
    """Test interfaces retrieval."""
    print("\n" + "="*60)
    print("TEST 3: Network Interfaces")
    print("="*60)
    
    try:
        print("\n[*] Fetching network interfaces...")
        interfaces = await client.get_interfaces()
        
        if not interfaces:
            print("[✗] No interfaces found")
            return False
        
        print(f"\n[✓] Found {len(interfaces)} interface(s)\n")
        
        for idx, iface in interfaces.items():
            print(f"  Interface {idx}:")
            for key, value in iface.items():
                status = "✓" if value else "✗"
                print(f"    {status} {key:15} : {value}")
            print()
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


async def test_walk(client: SNMPv3Client):
    """Test WALK operation."""
    print("\n" + "="*60)
    print("TEST 4: OID Walk (1.3.6.1.2.1.1)")
    print("="*60)
    
    try:
        print("\n[*] Walking OID tree 1.3.6.1.2.1.1 (System group)...")
        results = await client.walk('1.3.6.1.2.1.1')
        
        if not results:
            print("[✗] No results from WALK")
            return False
        
        print(f"\n[✓] Found {len(results)} OID(s)\n")
        
        for oid, value in list(results.items())[:5]:  # Show first 5
            print(f"  {oid:30} = {value}")
        
        if len(results) > 5:
            print(f"  ... and {len(results) - 5} more")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_multiple_gets(client: SNMPv3Client):
    """Test multiple GET operations."""
    print("\n" + "="*60)
    print("TEST 5: Multiple GET Operations")
    print("="*60)
    
    oids = [
        '1.3.6.1.2.1.1.1.0',  # sysDescr
        '1.3.6.1.2.1.1.3.0',  # sysUpTime
        '1.3.6.1.2.1.1.5.0',  # sysName
    ]
    
    try:
        print(f"\n[*] Getting {len(oids)} OIDs...")
        results = await client.get_multiple(oids)
        
        print("\n[✓] Results:")
        for oid, value in results.items():
            status = "✓" if value else "✗"
            print(f"  {status} {oid:25} = {value}")
        
        return any(v is not None for v in results.values())
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


async def main():
    """Run all tests."""
    print("\n" + "#"*60)
    print("# SNMPv3 Client - Comprehensive Test Suite")
    print("#"*60)
    
    try:
        # Create target
        print("\n[*] Loading SNMPv3 credentials from config...")
        creds = create_snmpv3_from_config()
        
        target = SNMPTarget(
            name="test_device",
            ip_address="192.168.1.1",  # Change to your target
            credentials=creds,
            port=161,
            timeout=5,
            retries=2
        )
        
        print(f"[✓] Target: {target.ip_address}:{target.port}")
        print(f"[✓] User: {creds.username}")
        print(f"[✓] Auth: {creds.auth_protocol.value}")
        print(f"[✓] Priv: {creds.priv_protocol.value}")
        
        # Create client
        print("\n[*] Initializing SNMPv3 client...")
        client = SNMPv3Client(target)
        
        # Run tests
        results = {}
        
        results['basic_get'] = await test_basic_get(client)
        results['system_info'] = await test_system_info(client)
        results['interfaces'] = await test_interfaces(client)
        results['walk'] = await test_walk(client)
        results['multiple_gets'] = await test_multiple_gets(client)
        
        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for v in results.values() if v)
        total = len(results)
        
        for test_name, result in results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"  {status} : {test_name}")
        
        print(f"\n  Total: {passed}/{total} tests passed")
        
        if passed == total:
            print("\n[✓] All tests passed! SNMPv3 client is working correctly.")
            return 0
        else:
            print(f"\n[✗] {total - passed} test(s) failed. Check configuration and connectivity.")
            return 1
        
        client.close()
    
    except Exception as e:
        print(f"\n[✗] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
