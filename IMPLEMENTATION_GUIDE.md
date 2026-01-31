# Beta-SNMP Implementation Guide

## Overview

This guide covers the implementation of SNMPv3 secure communication with the Cisco SG250-08 switch, configurable IP addresses, and HTTPS API integration with insecure SSL mode support.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Main Application                           │
│                   (main.py)                                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────┐    ┌──────────────────────┐       │
│  │   SNMP Module        │    │   API Module         │       │
│  │                      │    │                      │       │
│  │ ┌────────────────┐   │    │ ┌────────────────┐   │       │
│  │ │snmp_config.py  │   │    │ │api_client.py   │   │       │
│  │ │  - Credentials │   │    │ │  - HTTP/HTTPS  │   │       │
│  │ │  - Targets     │   │    │ │  - Insecure    │   │       │
│  │ │  - IPs         │   │    │ │  - Retries     │   │       │
│  │ └────────────────┘   │    │ └────────────────┘   │       │
│  │                      │    │                      │       │
│  │ ┌────────────────┐   │    │ ┌────────────────┐   │       │
│  │ │snmp_client.py  │   │    │ │requests        │   │       │
│  │ │  - SNMPv3      │   │    │ │  library       │   │       │
│  │ │  - Auth+Priv   │   │    │ └────────────────┘   │       │
│  │ │  - GET/SET     │   │    │                      │       │
│  │ └────────────────┘   │    └──────────────────────┘       │
│  │                      │                                     │
│  └──────────────────────┘                                     │
│           │                           │                       │
└───────────┼───────────────────────────┼───────────────────────┘
            │                           │
            ▼                           ▼
      SNMP Device              REST API Server
      (SG250-08 @              (HTTPS with
       192.168.1.28)           self-signed certs)
       Port 161                 Port 443
```

## 1. SNMPv3 Configuration

### 1.1 Credentials Storage

Credentials are stored in `config/snmp_targets.json`:

```json
{
  "targets": [
    {
      "name": "cisco_sg250",
      "ip_address": "192.168.1.28",
      "port": 161,
      "version": "v3",
      "credentials": {
        "username": "Alleria_W",
        "auth_password": "Vereesa_W",
        "auth_protocol": "SHA",
        "priv_password": "Windrunner",
        "priv_protocol": "AES128",
        "engine_boots": 0,
        "engine_time": 0
      },
      "timeout": 5,
      "retries": 3
    }
  ]
}
```

### 1.2 Key Components

**From your switch configuration:**
- **Username**: `Alleria_W`
- **Auth Password**: `Vereesa_W` (used to derive auth key)
- **Auth Protocol**: `SHA` (HMAC-SHA authentication)
- **Privacy Password**: `Windrunner` (used to derive encryption key)
- **Privacy Protocol**: `AES128` (AES encryption)

### 1.3 Python Implementation

```python
from config.snmp_config import (
    SNMPConfigManager,
    SNMPTarget,
    SNMPv3Credentials,
    AuthProtocol,
    PrivProtocol,
)

# Create credentials
creds = SNMPv3Credentials(
    username="Alleria_W",
    auth_password="Vereesa_W",
    auth_protocol=AuthProtocol.SHA,
    priv_password="Windrunner",
    priv_protocol=PrivProtocol.AES128,
)

# Create target
target = SNMPTarget(
    name="cisco_sg250",
    ip_address="192.168.1.28",
    credentials=creds,
)

# Manage configuration
config = SNMPConfigManager()
config.add_target(target)
config.save_config()
```

## 2. Configurable IP Addresses

### 2.1 Command Line Interface

Update IP address when launching the scraper:

```bash
# Update the IP address of an existing target
python main.py snmp --update-ip cisco_sg250 192.168.1.50

# Or add a new target with different IP
python main.py config --add switch_new 10.0.0.5
```

### 2.2 Programmatic Approach

```python
from config.snmp_config import SNMPConfigManager

config = SNMPConfigManager()

# Update IP dynamically
config.update_target_ip("cisco_sg250", "192.168.1.50")

# Get updated target
target = config.get_target("cisco_sg250")
print(f"New IP: {target.ip_address}")
```

### 2.3 Using Command Line Arguments

```python
# In your script, use argparse to accept IP as parameter
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--target-ip', default='192.168.1.28',
                    help='Target device IP address')
args = parser.parse_args()

# Use it in your SNMP operations
config = SNMPConfigManager()
config.update_target_ip('cisco_sg250', args.target_ip)
```

## 3. HTTPS API with Insecure SSL Mode

### 3.1 Understanding Insecure Mode

**Insecure mode** disables SSL certificate verification. This allows:
- ✅ Communication with self-signed certificates
- ✅ Testing environments without proper SSL setup
- ✅ Temporary debugging of SSL issues

**⚠️ WARNING:** This is a security risk and should ONLY be used:
- In development/testing environments
- On internal networks
- For temporary debugging
- **NEVER in production**

### 3.2 Python Implementation

```python
from api.api_client import create_insecure_client, HTTPSAPIClient

# Option 1: Using the insecure helper (recommended for testing)
api_client = create_insecure_client(
    "https://api.example.com",
    timeout=10,
    max_retries=3,
)

# Option 2: Creating client with insecure flag
api_client = HTTPSAPIClient(
    "https://api.example.com",
    insecure=True,  # Disables SSL verification
    timeout=10,
)

# Make requests
devices = api_client.get("/api/devices")
result = api_client.post("/api/devices",
    json_data={
        "name": "switch01",
        "ip": "192.168.1.28",
        "model": "SG250-08"
    }
)

api_client.close()
```

### 3.3 Command Line Usage

```bash
# GET request with insecure SSL
python main.py api \
  --url https://api.example.com \
  --endpoint /api/devices \
  --get \
  --insecure

# POST request with insecure SSL
python main.py api \
  --url https://api.example.com \
  --endpoint /api/devices \
  --post \
  --data '{"name": "switch01", "ip": "192.168.1.28"}' \
  --insecure

# Health check
python main.py api \
  --url https://api.example.com \
  --health \
  --insecure
```

### 3.4 SSL Certificate Warning Suppression

The API client automatically suppresses SSL warnings when in insecure mode:

```python
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Warnings are automatically suppressed in HTTPSAPIClient
# No need to do this manually
```

## 4. Complete Usage Examples

### 4.1 SNMP Operations

```bash
# List all configured targets
python main.py snmp --list-targets

# Get specific OID
python main.py snmp --target cisco_sg250 --get 1.3.6.1.2.1.1.1.0

# Get system information
python main.py snmp --target cisco_sg250 --system-info

# Get interfaces information
python main.py snmp --target cisco_sg250 --interfaces

# Set value (integer)
python main.py snmp --target cisco_sg250 \
  --set 1.3.6.1.2.1.1.6.0 "New Location" \
  --integer

# Walk OID tree
python main.py snmp --target cisco_sg250 --walk 1.3.6.1.2.1.2

# Update target IP
python main.py snmp --update-ip cisco_sg250 192.168.1.50
```

### 4.2 API Operations

```bash
# GET all devices (insecure)
python main.py api \
  --url https://api.example.com \
  --endpoint /api/devices \
  --get \
  --insecure

# POST new device (insecure)
python main.py api \
  --url https://api.example.com \
  --endpoint /api/devices \
  --post \
  --data '{"name": "switch01", "ip": "192.168.1.28"}' \
  --insecure

# Health check (insecure)
python main.py api \
  --url https://api.example.com \
  --health \
  --insecure
```

### 4.3 Configuration Management

```bash
# Add new target
python main.py config --add switch_backup 192.168.1.30

# Remove target
python main.py config --remove switch_backup

# List all targets
python main.py config
```

## 5. Python 3.14 Compatibility

This code is compatible with Python 3.14 (as of January 2026).

### 5.1 Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install specific packages
pip install "python-snmp[crypto]>=4.4.12"
pip install requests urllib3
pip install cryptography
```

### 5.2 Verification

```bash
# Check Python version
python --version

# Test imports
python -c "from snmp.snmp_client import SNMPv3Client; print('SNMPv3Client OK')"
python -c "from api.api_client import HTTPSAPIClient; print('HTTPSAPIClient OK')"
```

## 6. Security Best Practices

### 6.1 Credentials

- ✅ Store credentials in configuration files (as implemented)
- ✅ Use environment variables for sensitive data in production
- ❌ Don't commit credentials to Git
- ❌ Don't hardcode passwords in source code

### 6.2 SSL/TLS

- ✅ Use `insecure=False` in production
- ✅ Implement proper certificate management
- ✅ Use certificate pinning for critical APIs
- ❌ Never use `verify=False` in production
- ❌ Don't ignore SSL certificate errors in production

### 6.3 SNMP

- ✅ Always use SNMPv3 with authentication and privacy
- ✅ Use strong passwords for auth and privacy
- ✅ Restrict SNMP access with firewall rules
- ❌ Never use SNMPv1 or SNMPv2c
- ❌ Don't use default community strings

## 7. Troubleshooting

### 7.1 SNMP Connection Issues

```bash
# Enable debug logging
export DEBUG=1
python main.py snmp --target cisco_sg250 --system-info

# Check connectivity
ping 192.168.1.28

# Verify SNMP port
netstat -an | grep 161
```

### 7.2 API SSL Issues

```bash
# Test with curl (insecure)
curl -k https://api.example.com/health

# Check certificate
openssl s_client -connect api.example.com:443
```

### 7.3 Authentication Errors

```python
# Verify credentials match switch configuration
# Check username, auth password, privacy password
# Verify auth and privacy protocols

from config.snmp_config import create_snmpv3_from_config
creds = create_snmpv3_from_config()
print(f"Username: {creds.username}")
print(f"Auth Protocol: {creds.auth_protocol}")
print(f"Priv Protocol: {creds.priv_protocol}")
```

## 8. Project Structure

```
Beta-SNMP/
├── config/
│   ├── snmp_config.py          # Configuration manager
│   └── snmp_targets.json       # Target definitions
├── snmp/
│   ├── __init__.py
│   └── snmp_client.py          # SNMPv3 client
├── api/
│   ├── __init__.py
│   └── api_client.py           # HTTPS API client
├── main.py                     # CLI entry point
├── requirements.txt            # Dependencies
├── IMPLEMENTATION_GUIDE.md     # This file
└── README.md                   # Project overview
```

## 9. Next Steps

1. Install dependencies: `pip install -r requirements.txt`
2. Configure targets: Edit `config/snmp_targets.json`
3. Test SNMP: `python main.py snmp --list-targets`
4. Test API: `python main.py api --url https://... --health --insecure`
5. Integrate into your application

## 10. Support & Documentation

For more information:
- [PySNMP Documentation](http://pysnmp.com/)
- [Requests Library Docs](https://requests.readthedocs.io/)
- [SNMPv3 Security](https://en.wikipedia.org/wiki/SNMP#Version_3)

---

**Created**: 2026-01-31  
**Python Version**: 3.14+  
**Status**: Production Ready
