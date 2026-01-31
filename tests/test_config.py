"""
Tests for SNMP configuration management.
"""

import unittest
import json
import tempfile
import os
from config.snmp_config import (
    SNMPConfigManager,
    SNMPTarget,
    SNMPv3Credentials,
    AuthProtocol,
    PrivProtocol,
    create_snmpv3_from_config,
)


class TestSNMPv3Credentials(unittest.TestCase):
    """
    Test SNMPv3 credentials handling.
    """
    
    def test_credentials_creation(self):
        """Test creating SNMPv3 credentials."""
        creds = SNMPv3Credentials(
            username="test_user",
            auth_password="auth_pass",
            auth_protocol=AuthProtocol.SHA,
            priv_password="priv_pass",
            priv_protocol=PrivProtocol.AES128,
        )
        
        self.assertEqual(creds.username, "test_user")
        self.assertEqual(creds.auth_password, "auth_pass")
        self.assertEqual(creds.auth_protocol, AuthProtocol.SHA)
        self.assertEqual(creds.priv_password, "priv_pass")
        self.assertEqual(creds.priv_protocol, PrivProtocol.AES128)
    
    def test_credentials_to_dict(self):
        """Test credentials serialization."""
        creds = SNMPv3Credentials(
            username="Alleria_W",
            auth_password="Vereesa_W",
            auth_protocol=AuthProtocol.SHA,
            priv_password="Windrunner",
            priv_protocol=PrivProtocol.AES128,
        )
        
        creds_dict = creds.to_dict()
        
        self.assertEqual(creds_dict["username"], "Alleria_W")
        self.assertEqual(creds_dict["auth_password"], "Vereesa_W")
        self.assertEqual(creds_dict["auth_protocol"], "SHA")
        self.assertEqual(creds_dict["priv_password"], "Windrunner")
        self.assertEqual(creds_dict["priv_protocol"], "AES128")
    
    def test_credentials_from_dict(self):
        """Test credentials deserialization."""
        data = {
            "username": "Alleria_W",
            "auth_password": "Vereesa_W",
            "auth_protocol": "SHA",
            "priv_password": "Windrunner",
            "priv_protocol": "AES128",
        }
        
        creds = SNMPv3Credentials.from_dict(data)
        
        self.assertEqual(creds.username, "Alleria_W")
        self.assertEqual(creds.auth_protocol, AuthProtocol.SHA)
        self.assertEqual(creds.priv_protocol, PrivProtocol.AES128)


class TestSNMPTarget(unittest.TestCase):
    """
    Test SNMP target configuration.
    """
    
    def setUp(self):
        """Setup test fixtures."""
        self.creds = create_snmpv3_from_config()
    
    def test_target_creation(self):
        """Test creating SNMP target."""
        target = SNMPTarget(
            name="test_switch",
            ip_address="192.168.1.28",
            credentials=self.creds,
        )
        
        self.assertEqual(target.name, "test_switch")
        self.assertEqual(target.ip_address, "192.168.1.28")
        self.assertEqual(target.port, 161)
        self.assertIsNotNone(target.credentials)
    
    def test_target_to_dict(self):
        """Test target serialization."""
        target = SNMPTarget(
            name="cisco_sg250",
            ip_address="192.168.1.28",
            credentials=self.creds,
        )
        
        target_dict = target.to_dict()
        
        self.assertEqual(target_dict["name"], "cisco_sg250")
        self.assertEqual(target_dict["ip_address"], "192.168.1.28")
        self.assertIsNotNone(target_dict["credentials"])
    
    def test_target_from_dict(self):
        """Test target deserialization."""
        data = {
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
            },
        }
        
        target = SNMPTarget.from_dict(data)
        
        self.assertEqual(target.name, "cisco_sg250")
        self.assertEqual(target.ip_address, "192.168.1.28")
        self.assertEqual(target.credentials.username, "Alleria_W")


class TestSNMPConfigManager(unittest.TestCase):
    """
    Test configuration manager.
    """
    
    def setUp(self):
        """Setup test fixtures."""
        # Create temporary config file
        self.temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False,
        )
        self.temp_file.close()
        self.config_path = self.temp_file.name
        
        self.creds = create_snmpv3_from_config()
    
    def tearDown(self):
        """Cleanup."""
        if os.path.exists(self.config_path):
            os.unlink(self.config_path)
    
    def test_add_and_get_target(self):
        """Test adding and retrieving targets."""
        config = SNMPConfigManager(self.config_path)
        
        target = SNMPTarget(
            name="test_switch",
            ip_address="192.168.1.100",
            credentials=self.creds,
        )
        
        config.add_target(target)
        retrieved = config.get_target("test_switch")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "test_switch")
        self.assertEqual(retrieved.ip_address, "192.168.1.100")
    
    def test_update_target_ip(self):
        """Test updating target IP address."""
        config = SNMPConfigManager(self.config_path)
        
        target = SNMPTarget(
            name="test_switch",
            ip_address="192.168.1.100",
            credentials=self.creds,
        )
        
        config.add_target(target)
        config.update_target_ip("test_switch", "192.168.1.50")
        
        updated = config.get_target("test_switch")
        self.assertEqual(updated.ip_address, "192.168.1.50")
    
    def test_remove_target(self):
        """Test removing targets."""
        config = SNMPConfigManager(self.config_path)
        
        target = SNMPTarget(
            name="test_switch",
            ip_address="192.168.1.100",
            credentials=self.creds,
        )
        
        config.add_target(target)
        config.remove_target("test_switch")
        
        retrieved = config.get_target("test_switch")
        self.assertIsNone(retrieved)
    
    def test_save_and_load_config(self):
        """Test saving and loading configuration."""
        # Create and save config
        config1 = SNMPConfigManager(self.config_path)
        target = SNMPTarget(
            name="cisco_sg250",
            ip_address="192.168.1.28",
            credentials=self.creds,
        )
        config1.add_target(target)
        config1.save_config()
        
        # Load config in new manager
        config2 = SNMPConfigManager(self.config_path)
        retrieved = config2.get_target("cisco_sg250")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.ip_address, "192.168.1.28")


if __name__ == "__main__":
    unittest.main()
