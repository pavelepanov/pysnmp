"""USM rows use the wire username; engine IDs separate device credentials."""

import asyncio
from contextlib import AsyncExitStack

import pytest

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usmAesCfb128Protocol,
    usmHMAC192SHA256AuthProtocol,
)
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.smi.error import NoSuchInstanceError
from tests.end_to_end import SYS_DESCR, freePort

USER = "shared-user"
SECURITY_NAME = "device-user"
ENGINE_ID = OctetString(hexValue="8000000001")


def userRow(snmpEngine, engineId=ENGINE_ID):
    """Read the row by the same identity an incoming SNMPv3 message carries."""
    (entry,) = snmpEngine.getMibBuilder().importSymbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )
    index = entry.getInstIdFromIndices(engineId, USER)
    return entry, index


def test_security_name_is_a_column_not_the_user_index():
    with SnmpEngine() as snmpEngine:
        config.addV3User(
            snmpEngine, USER, securityEngineId=ENGINE_ID, securityName=SECURITY_NAME
        )
        entry, index = userRow(snmpEngine)

        assert (
            entry.getNode(entry.name + (2,) + index).syntax.asOctets() == USER.encode()
        )
        assert (
            entry.getNode(entry.name + (3,) + index).syntax.asOctets()
            == SECURITY_NAME.encode()
        )


def test_deleting_a_user_with_a_security_name_removes_its_row():
    with SnmpEngine() as snmpEngine:
        config.addV3User(
            snmpEngine, USER, securityEngineId=ENGINE_ID, securityName=SECURITY_NAME
        )
        config.delV3User(snmpEngine, USER, securityEngineId=ENGINE_ID)

        (entry,) = snmpEngine.getMibBuilder().importSymbols(
            "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
        )
        with pytest.raises(NoSuchInstanceError):
            entry.getNode(entry.name + (2,)).getNextNode(entry.name + (2,))


@pytest.mark.parametrize(
    "explicitEngineId", (False, True), ids=("discovery", "known-id")
)
async def test_a_security_name_can_differ_from_the_wire_username(explicitEngineId):
    """A real agent receives the username and the manager accepts its response."""
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        target = await createAgent(stack, ENGINE_ID, "authpassword1")
        authData = UsmUserData(
            USER,
            "authpassword1",
            authProtocol=usmHMAC192SHA256AuthProtocol,
            securityEngineId=ENGINE_ID if explicitEngineId else None,
            securityName=SECURITY_NAME,
        )

        result = await getDescription(manager, authData, target)

        assertDescription(result)


@pytest.mark.parametrize(
    "securityName", (None, SECURITY_NAME), ids=("default", "alias")
)
@pytest.mark.parametrize("privacy", (False, True), ids=("authNoPriv", "authPriv"))
async def test_engine_ids_isolate_the_same_username_with_different_keys(
    securityName, privacy
):
    """One manager polls two agents concurrently, then repeats with cached state."""
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        requests = []
        for number in (1, 2):
            engineId = OctetString(hexValue=f"800000000{number}")
            authKey = f"authpassword{number}"
            privKey = f"privpassword{number}" if privacy else None
            target = await createAgent(stack, engineId, authKey, privKey)
            authData = UsmUserData(
                USER,
                authKey,
                privKey,
                authProtocol=usmHMAC192SHA256AuthProtocol,
                privProtocol=usmAesCfb128Protocol,
                securityEngineId=engineId,
                securityName=securityName,
            )
            requests.append((authData, target))

        for _ in range(2):
            results = await asyncio.gather(
                *(
                    getDescription(manager, authData, target)
                    for authData, target in requests
                )
            )
            for result in results:
                assertDescription(result)


async def createAgent(stack, engineId, authKey, privKey=None):
    """Return the target of a local agent."""
    _, target = await startAgent(stack, engineId, authKey, privKey)
    return target


async def startAgent(stack, engineId, authKey, privKey=None):
    """Start a local agent with a known engine ID and no external simulator."""
    agent = await stack.enter_async_context(SnmpEngine(snmpEngineID=engineId))
    port = freePort()
    config.addTransport(
        agent, udp.domainName, udp.UdpTransport().openServerMode(("127.0.0.1", port))
    )
    config.addV3User(
        agent,
        USER,
        usmHMAC192SHA256AuthProtocol,
        authKey,
        usmAesCfb128Protocol if privKey else config.usmNoPrivProtocol,
        privKey,
    )
    config.addVacmUser(
        agent,
        3,
        USER,
        "authPriv" if privKey else "authNoPriv",
        (1, 3, 6, 1, 2, 1),
        (1, 3, 6, 1, 2, 1),
    )
    snmpContext = context.SnmpContext(agent)
    for responder in (
        cmdrsp.GetCommandResponder,
        cmdrsp.NextCommandResponder,
        cmdrsp.BulkCommandResponder,
        cmdrsp.SetCommandResponder,
    ):
        responder(agent, snmpContext)
    target = UdpTransportTarget(("127.0.0.1", port), timeout=0.5, retries=0)
    await target.resolve()
    return agent, target


async def getDescription(manager, authData, target):
    return await asyncio.wait_for(
        get_cmd(
            manager,
            authData,
            target,
            ContextData(),
            ObjectType(ObjectIdentity(SYS_DESCR)),
        ),
        timeout=5,
    )


def assertDescription(result):
    errorIndication, errorStatus, errorIndex, varBinds = result
    assert errorIndication is None, str(errorIndication)
    assert not errorStatus, errorStatus.prettyPrint()
    assert not errorIndex
    assert len(varBinds) == 1
    oid, value = varBinds[0]
    assert str(oid) == SYS_DESCR
    assert value.prettyPrint().startswith("PySNMP engine version")
