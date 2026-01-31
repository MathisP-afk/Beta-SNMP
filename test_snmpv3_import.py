#!/usr/bin/env python3
"""
Test script for SNMPv3Client import and instantiation.
"""

from config.snmp_config import SNMPTarget, SNMPv3Credentials, AuthProtocol, PrivProtocol
from snmp.snmp_client import SNMPv3Client

# Crée des credentials de test
creds = SNMPv3Credentials(
    username='test_user',
    auth_protocol=AuthProtocol.SHA,
    auth_password='auth_pass_12345',
    priv_protocol=PrivProtocol.AES128,
    priv_password='priv_pass_12345'
)

# Crée une cible
target = SNMPTarget(
    name='test_device',
    ip_address='192.168.1.1',
    credentials=creds
)

# Instancie le client
client = SNMPv3Client(target)
print('✓ SNMPv3Client instancié avec succès')
print(f'  Target: {target.ip_address}:{target.port}')
print(f'  User: {creds.username}')
print(f'  Auth: {creds.auth_protocol.value}')
print(f'  Priv: {creds.priv_protocol.value}')

print('\n✓ All imports and instantiation successful!')
