"""
Configuration manager for SNMPv3 credentials and target devices.
Handles secure storage and retrieval of authentication/privacy credentials.
"""

from dataclasses import dataclass
from typing import Optional, Dict, List
from enum import Enum
import os
import json


class AuthProtocol(Enum):
    """Supported SNMP authentication protocols."""
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"


class PrivProtocol(Enum):
    """Supported SNMP privacy (encryption) protocols."""
    DES = "DES"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"
    AES_CFB128 = "AES_CFB128"
    AES_CFB192 = "AES_CFB192"
    AES_CFB256 = "AES_CFB256"


@dataclass
class SNMPv3Credentials:
    """
    Container for SNMPv3 credentials (Auth & Privacy passwords).
    
    Attributes:
        username: SNMP user name (e.g., "Alleria_W")
        auth_password: Authentication password (e.g., "Vereesa_W")
        auth_protocol: Authentication algorithm (SHA, MD5, etc.)
        priv_password: Privacy/encryption password (e.g., "Windrunner")
        priv_protocol: Privacy algorithm (AES, DES, etc.)
        engine_boots: Engine boots counter (typically 0 for new sessions)
        engine_time: Engine time counter (typically 0 for new sessions)
    """
    username: str
    auth_password: str
    auth_protocol: AuthProtocol = AuthProtocol.SHA
    priv_password: str = None
    priv_protocol: PrivProtocol = PrivProtocol.AES128
    engine_boots: int = 0
    engine_time: int = 0

    def to_dict(self) -> Dict:
        """Convert credentials to dictionary for storage."""
        return {
            "username": self.username,
            "auth_password": self.auth_password,
            "auth_protocol": self.auth_protocol.value,
            "priv_password": self.priv_password,
            "priv_protocol": self.priv_protocol.value,
            "engine_boots": self.engine_boots,
            "engine_time": self.engine_time,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'SNMPv3Credentials':
        """Create credentials from dictionary."""
        return cls(
            username=data["username"],
            auth_password=data["auth_password"],
            auth_protocol=AuthProtocol(data.get("auth_protocol", "SHA")),
            priv_password=data.get("priv_password"),
            priv_protocol=PrivProtocol(data.get("priv_protocol", "AES128")),
            engine_boots=data.get("engine_boots", 0),
            engine_time=data.get("engine_time", 0),
        )


@dataclass
class SNMPTarget:
    """
    Represents an SNMP device target.
    
    Attributes:
        name: Display name for the target
        ip_address: IP address (IPv4 or IPv6)
        port: SNMP port (default 161)
        version: SNMP version ("v3")
        credentials: SNMPv3 credentials
        timeout: Request timeout in seconds
        retries: Number of retry attempts
    """
    name: str
    ip_address: str
    port: int = 161
    version: str = "v3"
    credentials: SNMPv3Credentials = None
    timeout: int = 5
    retries: int = 3

    def to_dict(self) -> Dict:
        """Convert target to dictionary."""
        return {
            "name": self.name,
            "ip_address": self.ip_address,
            "port": self.port,
            "version": self.version,
            "credentials": self.credentials.to_dict() if self.credentials else None,
            "timeout": self.timeout,
            "retries": self.retries,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'SNMPTarget':
        """Create target from dictionary."""
        credentials = None
        if data.get("credentials"):
            credentials = SNMPv3Credentials.from_dict(data["credentials"])
        
        return cls(
            name=data["name"],
            ip_address=data["ip_address"],
            port=data.get("port", 161),
            version=data.get("version", "v3"),
            credentials=credentials,
            timeout=data.get("timeout", 5),
            retries=data.get("retries", 3),
        )


class SNMPConfigManager:
    """
    Manager for SNMP configuration (targets and credentials).
    Handles configuration files and in-memory storage.
    """
    
    def __init__(self, config_file: str = "config/snmp_targets.json"):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to the JSON configuration file
        """
        self.config_file = config_file
        self.targets: Dict[str, SNMPTarget] = {}
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file if it exists."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for target_data in data.get("targets", []):
                        target = SNMPTarget.from_dict(target_data)
                        self.targets[target.name] = target
                print(f"✓ Configuration loaded from {self.config_file}")
            except Exception as e:
                print(f"✗ Error loading configuration: {e}")
        else:
            print(f"ℹ Configuration file not found: {self.config_file}")

    def save_config(self) -> None:
        """Save configuration to file."""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        try:
            data = {
                "targets": [target.to_dict() for target in self.targets.values()]
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"✓ Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"✗ Error saving configuration: {e}")

    def add_target(self, target: SNMPTarget) -> None:
        """Add or update an SNMP target."""
        self.targets[target.name] = target
        self.save_config()

    def remove_target(self, name: str) -> bool:
        """Remove an SNMP target."""
        if name in self.targets:
            del self.targets[name]
            self.save_config()
            return True
        return False

    def get_target(self, name: str) -> Optional[SNMPTarget]:
        """Get a target by name."""
        return self.targets.get(name)

    def get_all_targets(self) -> List[SNMPTarget]:
        """Get all configured targets."""
        return list(self.targets.values())

    def update_target_ip(self, name: str, new_ip: str) -> bool:
        """
        Update the IP address of a target.
        
        Args:
            name: Target name
            new_ip: New IP address
            
        Returns:
            True if successful, False if target not found
        """
        if name in self.targets:
            self.targets[name].ip_address = new_ip
            self.save_config()
            print(f"✓ Updated {name} IP to {new_ip}")
            return True
        print(f"✗ Target '{name}' not found")
        return False

    def list_targets(self) -> None:
        """Print all configured targets."""
        if not self.targets:
            print("No targets configured")
            return
        
        print("\n" + "="*60)
        print("Configured SNMP Targets")
        print("="*60)
        for name, target in self.targets.items():
            print(f"\nName: {name}")
            print(f"  IP: {target.ip_address}:{target.port}")
            print(f"  Version: {target.version}")
            if target.credentials:
                print(f"  User: {target.credentials.username}")
                print(f"  Auth: {target.credentials.auth_protocol.value}")
                print(f"  Priv: {target.credentials.priv_protocol.value}")
            print(f"  Timeout: {target.timeout}s | Retries: {target.retries}")
        print("="*60 + "\n")


# Example helper function to create credentials from the switch configuration
def create_snmpv3_from_config(
    username: str = "Alleria_W",
    auth_password: str = "Vereesa_W",
    auth_protocol: str = "SHA",
    priv_password: str = "Windrunner",
    priv_protocol: str = "AES128"
) -> SNMPv3Credentials:
    """
    Create SNMPv3 credentials from configuration parameters.
    
    This matches the credentials shown in the switch configuration:
    - Username: Alleria_W
    - Auth Password: Vereesa_W (for generating auth key)
    - Auth Protocol: SHA (selected in the switch)
    - Privacy Password: Windrunner (for generating privacy key)
    - Privacy Protocol: DES or AES128
    """
    return SNMPv3Credentials(
        username=username,
        auth_password=auth_password,
        auth_protocol=AuthProtocol[auth_protocol.upper()],
        priv_password=priv_password,
        priv_protocol=PrivProtocol[priv_protocol.upper()],
    )


if __name__ == "__main__":
    # Example usage
    config = SNMPConfigManager()
    
    # Create credentials from switch config
    creds = create_snmpv3_from_config()
    
    # Create a target for the Cisco SG250-08 switch
    target = SNMPTarget(
        name="cisco_sg250",
        ip_address="192.168.1.28",
        port=161,
        credentials=creds,
        timeout=5,
        retries=3
    )
    
    config.add_target(target)
    config.list_targets()
