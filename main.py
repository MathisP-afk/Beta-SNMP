#!/usr/bin/env python3
"""
Beta-SNMP Main Script

CLI tool for managing SNMP v3 queries and integrating with REST APIs.

Usage:
    python main.py snmp --target cisco_sg250 --get 1.3.6.1.2.1.1.1.0
    python main.py snmp --target cisco_sg250 --set 1.3.6.1.2.1.1.6.0 "new location"
    python main.py snmp --target cisco_sg250 --system-info
    python main.py snmp --target cisco_sg250 --interfaces
    python main.py snmp --list-targets
    python main.py snmp --update-ip cisco_sg250 192.168.1.50
    python main.py api --url https://192.168.1.15 --health --insecure --api-key vp1p-s8_iq-W08ZR5Wt9U6PYvwVGmWjwbzTLE4NsT1RoiY6bJzgFgfhrzcCkmRl_
"""

import argparse
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config.snmp_config import (
    SNMPConfigManager,
    SNMPTarget,
    create_snmpv3_from_config,
)
from snmp.snmp_client import SNMPv3Client
from api.api_client import HTTPSAPIClient, create_insecure_client


def main_snmp(args):
    """
    Handle SNMP operations.
    """
    config = SNMPConfigManager()
    
    # List targets
    if args.list_targets:
        config.list_targets()
        return 0
    
    # Update IP address
    if args.update_ip:
        target_name, new_ip = args.update_ip
        success = config.update_target_ip(target_name, new_ip)
        return 0 if success else 1
    
    # Operations requiring a target
    if not args.target:
        print("Error: --target is required for SNMP operations")
        return 1
    
    target = config.get_target(args.target)
    if not target:
        print(f"Error: Target '{args.target}' not found")
        config.list_targets()
        return 1
    
    try:
        client = SNMPv3Client(target)
        
        # GET operation
        if args.get:
            print(f"\n[GET] OID: {args.get}")
            result = client.get(args.get)
            print(f"Result: {result}\n")
            return 0
        
        # SET operation
        if args.set:
            oid, value = args.set
            print(f"\n[SET] OID: {oid} = {value}")
            value_type = "integer" if args.integer else None
            success = client.set(oid, value, value_type)
            print()
            return 0 if success else 1
        
        # System info
        if args.system_info:
            print("\n[SYSTEM INFO]")
            info = client.get_system_info()
            for key, value in info.items():
                print(f"  {key:15s}: {value}")
            print()
            return 0
        
        # Interfaces info
        if args.interfaces:
            print("\n[INTERFACES]")
            interfaces = client.get_interfaces()
            for idx, iface_info in interfaces.items():
                print(f"  Interface {idx}:")
                for key, value in iface_info.items():
                    print(f"    {key:15s}: {value}")
            print()
            return 0
        
        # Walk OID tree
        if args.walk:
            print(f"\n[WALK] Root OID: {args.walk}")
            results = client.walk(args.walk)
            for oid, value in list(results.items())[:10]:
                print(f"  {oid}: {value}")
            if len(results) > 10:
                print(f"  ... and {len(results) - 10} more")
            print()
            return 0
        
        # If no operation specified
        print("Error: Specify an operation (--get, --set, --system-info, etc.)")
        return 1
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        client.close()


def main_api(args):
    """
    Handle API operations.
    """
    if not args.url:
        print("Error: --url is required for API operations")
        return 1
    
    # Determine if we should use insecure mode
    insecure = args.insecure or "https" in args.url
    
    try:
        if insecure and args.insecure:
            print("\n⚠️  Starting API client in INSECURE mode (testing/development only)")
            api_client = create_insecure_client(
                args.url,
                api_key=args.api_key,
                timeout=args.timeout,
                max_retries=args.retries,
            )
        else:
            api_client = HTTPSAPIClient(
                args.url,
                api_key=args.api_key,
                insecure=False,
                timeout=args.timeout,
                max_retries=args.retries,
            )
        
        endpoint = args.endpoint or "/"
        
        # GET request
        if args.get:
            print(f"\n[GET] {args.url}{endpoint}")
            if args.params:
                params = json.loads(args.params)
                result = api_client.get(endpoint, params=params)
            else:
                result = api_client.get(endpoint)
            print(f"Result: {json.dumps(result, indent=2)}\n")
            return 0
        
        # POST request
        if args.post:
            print(f"\n[POST] {args.url}{endpoint}")
            if args.data:
                data = json.loads(args.data)
                result = api_client.post(endpoint, json_data=data)
            else:
                result = api_client.post(endpoint)
            print(f"Result: {json.dumps(result, indent=2)}\n")
            return 0
        
        # Health check
        if args.health:
            print(f"\n[HEALTH CHECK] {args.url}/health")
            healthy = api_client.health_check()
            if healthy:
                print("✓ API is healthy\n")
                return 0
            else:
                print("✗ API health check failed\n")
                return 1
        
        # If no operation specified
        print("Error: Specify an operation (--get, --post, --health, etc.)")
        return 1
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        api_client.close()


def main_config(args):
    """
    Handle configuration operations.
    """
    config = SNMPConfigManager()
    
    # Add target
    if args.add:
        name, ip = args.add
        creds = create_snmpv3_from_config()
        target = SNMPTarget(
            name=name,
            ip_address=ip,
            credentials=creds,
        )
        config.add_target(target)
        print(f"✓ Added target '{name}' with IP {ip}")
        return 0
    
    # Remove target
    if args.remove:
        success = config.remove_target(args.remove)
        if success:
            print(f"✓ Removed target '{args.remove}'")
            return 0
        else:
            print(f"✗ Target '{args.remove}' not found")
            return 1
    
    # List targets
    config.list_targets()
    return 0


def create_parser():
    """
    Create and configure argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Beta-SNMP: SNMPv3 client with REST API integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  SNMP Operations:
    python main.py snmp --target cisco_sg250 --get 1.3.6.1.2.1.1.1.0
    python main.py snmp --target cisco_sg250 --system-info
    python main.py snmp --list-targets
    python main.py snmp --update-ip cisco_sg250 192.168.1.50
  
  API Operations:
    python main.py api --url https://192.168.1.15 --health --insecure --api-key YOUR_KEY
    python main.py api --url https://api.example.com --endpoint /devices --get --insecure
    python main.py api --url https://api.example.com --endpoint /devices --post --data '{"name": "sw1"}' --insecure
  
  Configuration:
    python main.py config --add myswitch 192.168.1.100
    python main.py config --remove myswitch
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # SNMP subcommand
    snmp_parser = subparsers.add_parser("snmp", help="SNMP operations")
    snmp_group = snmp_parser.add_argument_group("operations")
    snmp_group.add_argument("--get", metavar="OID", help="GET specific OID")
    snmp_group.add_argument("--set", nargs=2, metavar=("OID", "VALUE"), help="SET OID to value")
    snmp_group.add_argument("--walk", metavar="OID", help="WALK OID tree")
    snmp_group.add_argument("--system-info", action="store_true", help="Get system information")
    snmp_group.add_argument("--interfaces", action="store_true", help="Get interfaces information")
    snmp_group.add_argument("--list-targets", action="store_true", help="List all configured targets")
    snmp_group.add_argument("--update-ip", nargs=2, metavar=("TARGET", "NEW_IP"), help="Update target IP")
    
    snmp_parser.add_argument("--target", metavar="NAME", help="Target name from configuration")
    snmp_parser.add_argument("--integer", action="store_true", help="Treat SET value as integer")
    snmp_parser.set_defaults(func=main_snmp)
    
    # API subcommand
    api_parser = subparsers.add_parser("api", help="API operations")
    api_group = api_parser.add_argument_group("operations")
    api_group.add_argument("--get", action="store_true", help="Perform GET request")
    api_group.add_argument("--post", action="store_true", help="Perform POST request")
    api_group.add_argument("--health", action="store_true", help="Check API health")
    
    api_parser.add_argument("--url", metavar="URL", help="API base URL (e.g., https://192.168.1.15)")
    api_parser.add_argument("--endpoint", metavar="PATH", help="API endpoint (default: /)")
    api_parser.add_argument("--data", metavar="JSON", help="POST data as JSON")
    api_parser.add_argument("--params", metavar="JSON", help="GET parameters as JSON")
    api_parser.add_argument("--api-key", metavar="KEY", help="API key for authentication")
    api_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL verification (TESTING ONLY!)"
    )
    api_parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    api_parser.add_argument("--retries", type=int, default=3, help="Retry attempts (default: 3)")
    api_parser.set_defaults(func=main_api)
    
    # Config subcommand
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_group = config_parser.add_argument_group("operations")
    config_group.add_argument("--add", nargs=2, metavar=("NAME", "IP"), help="Add new target")
    config_group.add_argument("--remove", metavar="NAME", help="Remove target")
    config_parser.set_defaults(func=main_config)
    
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    exit_code = args.func(args)
    sys.exit(exit_code)
