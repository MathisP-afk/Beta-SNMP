#!/usr/bin/env python3
"""
Module d'envoi de requetes SNMP v2c et v3.
Utilise pysnmp HLAPI asyncio pour GET, GETNEXT, SET et TRAP.
Partage entre les GUIs Centrale_SQLite et Central_Postgre.
"""

import time
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine,
        CommunityData,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        get_cmd,
        next_cmd,
        set_cmd,
        send_notification,
        NotificationType,
    )
    from pysnmp.entity import config
    from pysnmp.proto.rfc1902 import OctetString, Integer32
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False


@dataclass
class SNMPResult:
    success: bool
    error_message: str = ""
    varbinds: List[Tuple[str, str]] = field(default_factory=list)
    elapsed_ms: float = 0.0


async def _create_target(host: str, port: int):
    """Cree un UdpTransportTarget compatible pysnmp 7.x et anciennes versions."""
    try:
        return await UdpTransportTarget.create((host, port), timeout=5, retries=1)
    except (TypeError, AttributeError):
        return UdpTransportTarget((host, port), timeout=5, retries=1)


def _build_auth_data(version: str, community: str = "public",
                     username: str = "", auth_password: str = "",
                     priv_password: str = ""):
    """Retourne CommunityData (v2c) ou UsmUserData (v3)."""
    if version == "v2c":
        return CommunityData(community, mpModel=1)
    return UsmUserData(
        username, auth_password, priv_password,
        authProtocol=config.USM_AUTH_HMAC96_SHA,
        privProtocol=config.USM_PRIV_CBC56_DES,
    )


async def send_get(host: str, port: int, oid: str, version: str = "v2c",
                   community: str = "public", username: str = "",
                   auth_password: str = "", priv_password: str = "") -> SNMPResult:
    """Envoie un GET SNMP."""
    t0 = time.monotonic()
    try:
        engine = SnmpEngine()
        target = await _create_target(host, port)
        auth = _build_auth_data(version, community, username, auth_password, priv_password)

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            engine, auth, target, ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        elapsed = (time.monotonic() - t0) * 1000
        if errorIndication:
            return SNMPResult(False, str(errorIndication), elapsed_ms=elapsed)
        if errorStatus:
            return SNMPResult(False, f"{errorStatus.prettyPrint()} (index {errorIndex})", elapsed_ms=elapsed)

        vb = [(o.prettyPrint(), v.prettyPrint()) for o, v in varBinds]
        return SNMPResult(True, varbinds=vb, elapsed_ms=elapsed)
    except Exception as exc:
        return SNMPResult(False, str(exc), elapsed_ms=(time.monotonic() - t0) * 1000)


async def send_getnext(host: str, port: int, oid: str, version: str = "v2c",
                       community: str = "public", username: str = "",
                       auth_password: str = "", priv_password: str = "") -> SNMPResult:
    """Envoie un GETNEXT SNMP."""
    t0 = time.monotonic()
    try:
        engine = SnmpEngine()
        target = await _create_target(host, port)
        auth = _build_auth_data(version, community, username, auth_password, priv_password)

        errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
            engine, auth, target, ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        elapsed = (time.monotonic() - t0) * 1000
        if errorIndication:
            return SNMPResult(False, str(errorIndication), elapsed_ms=elapsed)
        if errorStatus:
            return SNMPResult(False, f"{errorStatus.prettyPrint()} (index {errorIndex})", elapsed_ms=elapsed)

        vb = [(o.prettyPrint(), v.prettyPrint()) for o, v in varBinds]
        return SNMPResult(True, varbinds=vb, elapsed_ms=elapsed)
    except Exception as exc:
        return SNMPResult(False, str(exc), elapsed_ms=(time.monotonic() - t0) * 1000)


async def send_set(host: str, port: int, oid: str, value: str,
                   value_type: str = "string", version: str = "v2c",
                   community: str = "public", username: str = "",
                   auth_password: str = "", priv_password: str = "") -> SNMPResult:
    """Envoie un SET SNMP."""
    t0 = time.monotonic()
    try:
        engine = SnmpEngine()
        target = await _create_target(host, port)
        auth = _build_auth_data(version, community, username, auth_password, priv_password)

        if value_type == "integer":
            typed_value = Integer32(int(value))
        else:
            typed_value = OctetString(value)

        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            engine, auth, target, ContextData(),
            ObjectType(ObjectIdentity(oid), typed_value),
        )

        elapsed = (time.monotonic() - t0) * 1000
        if errorIndication:
            return SNMPResult(False, str(errorIndication), elapsed_ms=elapsed)
        if errorStatus:
            return SNMPResult(False, f"{errorStatus.prettyPrint()} (index {errorIndex})", elapsed_ms=elapsed)

        vb = [(o.prettyPrint(), v.prettyPrint()) for o, v in varBinds]
        return SNMPResult(True, varbinds=vb, elapsed_ms=elapsed)
    except Exception as exc:
        return SNMPResult(False, str(exc), elapsed_ms=(time.monotonic() - t0) * 1000)


async def send_trap(host: str, port: int, trap_oid: str,
                    varbind_oid: str = "", varbind_value: str = "",
                    version: str = "v2c", community: str = "public",
                    username: str = "", auth_password: str = "",
                    priv_password: str = "") -> SNMPResult:
    """Envoie un TRAP SNMP."""
    t0 = time.monotonic()
    try:
        engine = SnmpEngine()
        target = await _create_target(host, port)
        auth = _build_auth_data(version, community, username, auth_password, priv_password)

        notification = NotificationType(ObjectIdentity(trap_oid))
        if varbind_oid and varbind_value:
            notification = notification.add_varbinds(
                ObjectType(ObjectIdentity(varbind_oid), OctetString(varbind_value))
            )

        errorIndication, errorStatus, errorIndex, varBinds = await send_notification(
            engine, auth, target, ContextData(),
            'trap', notification,
        )

        elapsed = (time.monotonic() - t0) * 1000
        if errorIndication:
            return SNMPResult(False, str(errorIndication), elapsed_ms=elapsed)

        return SNMPResult(True, elapsed_ms=elapsed)
    except Exception as exc:
        return SNMPResult(False, str(exc), elapsed_ms=(time.monotonic() - t0) * 1000)
