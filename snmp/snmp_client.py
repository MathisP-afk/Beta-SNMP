"""
SNMPv3 client for secure communication with network devices.
Supports authentication and privacy encryption.
Updated for pysnmp 7.x modern API with Python 3.14+ support.
"""

from typing import Optional, List, Dict, Any
import logging
import asyncio
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, UsmUserData, ContextData, ObjectType, ObjectIdentity,
    get_cmd, set_cmd, bulk_cmd,
    UdpTransportTarget,
    Integer
)
from pysnmp.proto.rfc1902 import Integer32
from pysnmp.hlapi.v3arch import (
    USM_AUTH_HMAC96_SHA, USM_AUTH_HMAC96_MD5,
    USM_PRIV_CFB128_AES, USM_PRIV_CFB192_AES, USM_PRIV_CFB256_AES,
    USM_PRIV_CBC56_DES,
)
from config.snmp_config import SNMPTarget, SNMPv3Credentials


# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class SNMPv3Client:
    """
    SNMPv3 client for querying and managing SNMP devices.
    Compatible with pysnmp 7.x and Python 3.14+
    
    Features:
    - SNMPv3 with authentication (MD5, SHA) and privacy (DES, AES)
    - GET, SET, WALK, BULKWALK operations (async-based)
    - Automatic retry and timeout handling
    - Detailed error reporting
    """
    
    def __init__(self, target: SNMPTarget):
        """
        Initialize SNMP client for a target device.
        
        Args:
            target: SNMPTarget instance with credentials and connection params
        """
        self.target = target
        self.snmp_engine = SnmpEngine()
        self._setup_user_data()
        logger.info(f"SNMPv3 client initialized for {target.ip_address}")
    
    def _setup_user_data(self) -> None:
        """
        Setup SNMPv3 user data with auth and privacy parameters.
        """
        creds = self.target.credentials
        if not creds:
            raise ValueError("SNMPv3 credentials required")
        
        # Map auth protocol
        auth_proto = USM_AUTH_HMAC96_SHA
        if "MD5" in creds.auth_protocol.value:
            auth_proto = USM_AUTH_HMAC96_MD5
        
        # Map privacy protocol  
        priv_proto = USM_PRIV_CFB128_AES
        if "DES" in creds.priv_protocol.value:
            priv_proto = USM_PRIV_CBC56_DES
        elif "AES128" in creds.priv_protocol.value:
            priv_proto = USM_PRIV_CFB128_AES
        elif "AES192" in creds.priv_protocol.value:
            priv_proto = USM_PRIV_CFB192_AES
        elif "AES256" in creds.priv_protocol.value:
            priv_proto = USM_PRIV_CFB256_AES
        
        # Create user data with credentials
        try:
            self.user_data = UsmUserData(
                userName=creds.username,
                authKey=creds.auth_password,
                privKey=creds.priv_password,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
            
            logger.debug(
                f"SNMPv3 user '{creds.username}' configured with "
                f"{creds.auth_protocol.value} + {creds.priv_protocol.value}"
            )
        except Exception as e:
            logger.error(f"Failed to setup SNMPv3 user data: {e}")
            raise
    
    async def _get_transport_target(self) -> UdpTransportTarget:
        """
        Setup UDP transport target asynchronously.
        """
        transport_target = await UdpTransportTarget.create(
            self.target.ip_address,
            self.target.port,
            timeout=self.target.timeout,
            retries=self.target.retries,
        )
        
        logger.debug(
            f"Transport to {self.target.ip_address}:{self.target.port} "
            f"(timeout={self.target.timeout}s, retries={self.target.retries})"
        )
        return transport_target
    
    async def get(self, oid: str) -> Optional[Any]:
        """
        Perform SNMP GET operation.
        
        Args:
            oid: Object identifier (e.g., "1.3.6.1.2.1.1.1.0")
            
        Returns:
            Value or None if error
        """
        try:
            transport_target = await self._get_transport_target()
            
            error_indication, error_status, error_index, var_binds = await get_cmd(
                self.snmp_engine,
                self.user_data,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            
            if error_indication:
                logger.error(f"SNMP GET error: {error_indication}")
                return None
            
            if error_status:
                logger.error(
                    f"SNMP GET error status: {error_status.prettyPrint()} "
                    f"at {error_index}"
                )
                return None
            
            # Extract value from var_binds
            for name, value in var_binds:
                logger.info(f"GET {oid} = {value}")
                return value
        
        except Exception as e:
            logger.error(f"Exception during GET: {e}")
            return None
    
    async def get_multiple(self, oids: List[str]) -> Dict[str, Any]:
        """
        Perform SNMP GET for multiple OIDs.
        
        Args:
            oids: List of OIDs
            
        Returns:
            Dictionary mapping OID to value
        """
        results = {}
        for oid in oids:
            value = await self.get(oid)
            results[oid] = value
        return results
    
    async def set(self, oid: str, value: Any, value_type: str = None) -> bool:
        """
        Perform SNMP SET operation.
        
        Args:
            oid: Object identifier
            value: New value
            value_type: Type hint ('integer', 'string', 'timeticks', etc.)
            
        Returns:
            True if successful
        """
        try:
            transport_target = await self._get_transport_target()
            
            # Determine value type
            snmp_value = value
            if value_type == 'integer' or isinstance(value, int):
                snmp_value = Integer32(value)
            
            error_indication, error_status, error_index, var_binds = await set_cmd(
                self.snmp_engine,
                self.user_data,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(oid), snmp_value),
            )
            
            if error_indication:
                logger.error(f"SNMP SET error: {error_indication}")
                return False
            
            if error_status:
                logger.error(
                    f"SNMP SET error status: {error_status.prettyPrint()} "
                    f"at {error_index}"
                )
                return False
            
            logger.info(f"SET {oid} = {value} [OK]")
            return True
        
        except Exception as e:
            logger.error(f"Exception during SET: {e}")
            return False
    
    async def walk(self, oid: str) -> Dict[str, Any]:
        """
        Perform SNMP WALK (GET-NEXT tree walk).
        
        Args:
            oid: Root OID to walk
            
        Returns:
            Dictionary of OID: value pairs
        """
        results = {}
        try:
            transport_target = await self._get_transport_target()
            
            async for error_indication, error_status, error_index, var_binds in bulk_cmd(
                self.snmp_engine,
                self.user_data,
                transport_target,
                ContextData(),
                0, 25,  # nonRepeaters, maxRepetitions
                ObjectType(ObjectIdentity(oid)),
            ):
                if error_indication:
                    logger.error(f"SNMP WALK error: {error_indication}")
                    break
                
                if error_status:
                    logger.error(
                        f"SNMP WALK error status: {error_status.prettyPrint()} "
                        f"at {error_index}"
                    )
                    break
                
                for name, value in var_binds:
                    oid_str = str(name)
                    results[oid_str] = str(value)
                    logger.debug(f"  {oid_str} = {value}")
            
            logger.info(f"WALK returned {len(results)} objects")
            return results
        
        except Exception as e:
            logger.error(f"Exception during WALK: {e}")
            return {}
    
    async def get_system_info(self) -> Dict[str, str]:
        """
        Get basic system information from device.
        
        Returns:
            Dictionary with system info
        """
        system_oids = {
            'description': '1.3.6.1.2.1.1.1.0',
            'object_id': '1.3.6.1.2.1.1.2.0',
            'uptime': '1.3.6.1.2.1.1.3.0',
            'contact': '1.3.6.1.2.1.1.4.0',
            'name': '1.3.6.1.2.1.1.5.0',
            'location': '1.3.6.1.2.1.1.6.0',
            'services': '1.3.6.1.2.1.1.7.0',
        }
        
        info = {}
        for key, oid in system_oids.items():
            value = await self.get(oid)
            info[key] = str(value) if value else "N/A"
        
        return info
    
    async def get_interfaces(self) -> Dict[int, Dict[str, Any]]:
        """
        Get network interfaces information.
        
        Returns:
            Dictionary indexed by interface number
        """
        interfaces = {}
        
        # Get interface count
        num_interfaces_value = await self.get('1.3.6.1.2.1.2.1.0')
        try:
            num_interfaces = int(str(num_interfaces_value))
        except:
            logger.error("Could not determine number of interfaces")
            return interfaces
        
        logger.info(f"Found {num_interfaces} interfaces")
        
        # Get interface details
        for i in range(1, num_interfaces + 1):
            interfaces[i] = {
                'name': await self.get(f'1.3.6.1.2.1.2.2.1.2.{i}'),
                'type': await self.get(f'1.3.6.1.2.1.2.2.1.3.{i}'),
                'mtu': await self.get(f'1.3.6.1.2.1.2.2.1.4.{i}'),
                'speed': await self.get(f'1.3.6.1.2.1.2.2.1.5.{i}'),
                'admin_status': await self.get(f'1.3.6.1.2.1.2.2.1.7.{i}'),
                'oper_status': await self.get(f'1.3.6.1.2.1.2.2.1.8.{i}'),
            }
        
        return interfaces
    
    def close(self) -> None:
        """
        Close SNMP session and clean up resources.
        """
        try:
            logger.info(f"SNMP session closed for {self.target.ip_address}")
        except Exception as e:
            logger.warning(f"Error closing SNMP session: {e}")


async def main():
    # Example usage
    from config.snmp_config import create_snmpv3_from_config, SNMPTarget
    
    # Create target
    creds = create_snmpv3_from_config()
    target = SNMPTarget(
        name="test_switch",
        ip_address="192.168.1.28",
        credentials=creds
    )
    
    # Create client and test
    try:
        client = SNMPv3Client(target)
        
        # Get system info
        print("\nGetting system information...")
        info = await client.get_system_info()
        for key, value in info.items():
            print(f"  {key}: {value}")
        
        # Get interfaces
        print("\nGetting interfaces...")
        interfaces = await client.get_interfaces()
        for idx, iface_info in interfaces.items():
            print(f"  Interface {idx}: {iface_info['name']}")
        
        client.close()
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
