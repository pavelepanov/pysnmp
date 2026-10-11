"""Credential cleanup and discovery failures must not break other requests."""

import asyncio
import socket
import warnings
from contextlib import AsyncExitStack
from unittest.mock import Mock

import pytest
from pyasn1.error import PyAsn1Error

from pysnmp.carrier.asyncio.dgram import udp, udp6
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.error import PySnmpError, PySnmpWeakCryptoWarning
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UsmUserData,
    send_notification,
    usmHMAC192SHA256AuthProtocol,
)
from pysnmp.hlapi.asyncio.cmdgen import lcd
from pysnmp.hlapi.asyncio.ntforg import lcd as notificationLcd
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.smi.error import NoSuchInstanceError
from tests.end_to_end import COLD_START, SNMP_TRAP_OID
from tests.test_lcd_key_rotation import StubTransportTarget
from tests.test_usm_user_identity import (
    USER,
    assertDescription,
    getDescription,
    startAgent,
)


def user(password="authpassword1", engineId=None):  # noqa: S107 - local test credentials
    return UsmUserData(
        USER,
        password,
        authProtocol=usmHMAC192SHA256AuthProtocol,
        securityEngineId=engineId,
    )


def assertUser(engine, engineId):
    (entry,) = engine.getMibBuilder().importSymbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )
    index = entry.getInstIdFromIndices(engineId, USER)
    assert entry.getNode(entry.name + (2,) + index).syntax.asOctets() == USER.encode()


async def test_unconfigure_template_preserves_explicit_peer():
    async with SnmpEngine() as manager:
        engineId = OctetString(hexValue="8000000001")
        explicit, template = user(engineId=engineId), user()
        lcd.configure(manager, explicit, StubTransportTarget())
        lcd.configure(manager, template, StubTransportTarget())
        lcd.unconfigure(manager, template)
        assertUser(manager, engineId)


@pytest.mark.parametrize("explicitId", (False, True))
async def test_unconfigure_preserves_another_peers_pending_reply(
    explicitId, monkeypatch
):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        engineId = OctetString(hexValue="8000000001")
        _, targetA = await startAgent(stack, engineId, "authpassword1")
        passwordB = "authpassword1" if explicitId else "authpassword2"
        _, targetB = await startAgent(
            stack, OctetString(hexValue="8000000002"), passwordB
        )
        authA = user(engineId=engineId if explicitId else None)
        authB = user(passwordB)
        assertDescription(await getDescription(manager, authA, targetA))
        assertDescription(await getDescription(manager, authB, targetB))
        transport = manager.transportDispatcher.getTransport(targetA.transportDomain)
        receive = transport._cbFun
        ready = asyncio.Event()
        held = []

        def holdResponse(transport, address, message):
            if address == targetA.transportAddr:
                held.append((transport, address, message))
                ready.set()
            else:
                receive(transport, address, message)

        monkeypatch.setattr(transport, "_cbFun", holdResponse)
        request = asyncio.create_task(getDescription(manager, authA, targetA))
        await asyncio.wait_for(ready.wait(), 2)
        lcd.unconfigure(manager, authB)
        for response in held:
            receive(*response)
        assertDescription(await request)


async def test_explicit_and_discovered_profiles_can_share_a_user():
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        engineId = OctetString(hexValue="8000000001")
        _, target = await startAgent(stack, engineId, "authpassword1")
        explicit, discovered = user(engineId=engineId), user()
        for authData in (explicit, discovered):
            assertDescription(await getDescription(manager, authData, target))
        lcd.unconfigure(manager, discovered)
        assertUser(manager, engineId)
        assertDescription(await getDescription(manager, explicit, target))
        lcd.unconfigure(manager)
        assert all(not entries for entries in lcd._getCache(manager).values())
        assert config.getTransport(manager, target.transportDomain) is None


async def request(manager, authData, target, operation):
    if operation == "get":
        return await getDescription(manager, authData, target)
    return await asyncio.wait_for(
        send_notification(
            manager,
            authData,
            target,
            ContextData(),
            "inform",
            [ObjectType(ObjectIdentity(SNMP_TRAP_OID), COLD_START)],
        ),
        2,
    )


@pytest.mark.parametrize("operation", ("get", "inform"))
async def test_warnings_as_errors_reach_the_caller(operation):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        agent, target = await startAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", PySnmpWeakCryptoWarning)
            config.addV3User(
                agent, USER, config.usmHMACMD5AuthProtocol, "authpassword1"
            )
        with warnings.catch_warnings():
            warnings.simplefilter("error", PySnmpWeakCryptoWarning)
            with pytest.raises(PySnmpWeakCryptoWarning):
                await request(
                    manager, UsmUserData(USER, "authpassword1"), target, operation
                )


@pytest.mark.parametrize("operation", ("get", "inform"))
async def test_late_configuration_error_completes_request(operation, monkeypatch):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        agent, target = await startAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        ntfrcv.NotificationReceiver(agent, lambda *args: None)
        failure = PySnmpError("User configuration failed after discovery")
        addUser = config.addV3User

        def failRegistration(engine, *args, **kwargs):
            if engine is manager:
                raise failure
            return addUser(engine, *args, **kwargs)

        monkeypatch.setattr(config, "addV3User", failRegistration)
        result = await request(manager, user(), target, operation)
        assert result[0] is failure
        assert not manager.transportDispatcher.jobsArePending()


async def test_inform_fanout_uses_each_targets_credentials():
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        received = []
        for number in (1, 2):
            agent, target = await startAgent(
                stack,
                OctetString(hexValue=f"800000000{number}"),
                f"authpassword{number}",
            )
            ntfrcv.NotificationReceiver(agent, lambda *args: received.append(args))
            target.tagList = "shared-receivers"
            result = await request(
                manager, user(f"authpassword{number}"), target, "inform"
            )
            assert result[0] is None, str(result[0])
        # The second call addresses both targets carrying the common tag.
        assert len(received) == 3
        notificationLcd.unconfigure(manager)
        assert all(
            not entries for entries in notificationLcd._getCache(manager).values()
        )
        assert all(not entries for entries in lcd._getCache(manager).values())


async def test_failed_rotation_does_not_leave_a_stale_user_cache(monkeypatch):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        _, target = await startAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        assertDescription(await getDescription(manager, user(), target))
        addUser = config.addV3User

        def failAfterWrite(engine, *args, **kwargs):
            addUser(engine, *args, **kwargs)
            raise PySnmpError("User configuration failed after writing the row")

        with monkeypatch.context() as patch:
            patch.setattr(config, "addV3User", failAfterWrite)
            with pytest.raises(PySnmpError):
                await getDescription(manager, user("authpassword2"), target)
        assertDescription(await getDescription(manager, user(), target))


@pytest.mark.skipif(not socket.has_ipv6, reason="IPv6 is unavailable")
async def test_ipv6_discovered_user_is_removed_with_its_configuration():
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        agent, _ = await startAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        transport = udp6.Udp6Transport().openServerMode(("::1", 0))
        config.addTransport(agent, udp6.domainName, transport)
        await transport._lport
        port = transport.transport.get_extra_info("sockname")[1]
        target = Udp6TransportTarget(("::1", port), timeout=0.5, retries=0)
        assertDescription(await getDescription(manager, user(), target))
        lcd.unconfigure(manager)
        assert all(not entries for entries in lcd._getCache(manager).values())


async def test_cleanup_after_an_initial_user_registration_failure(monkeypatch):
    async with SnmpEngine() as manager:
        addUser = config.addV3User

        def failAfterWrite(*args, **kwargs):
            addUser(*args, **kwargs)
            raise PySnmpError("Initial registration failed after writing the row")

        monkeypatch.setattr(config, "addV3User", failAfterWrite)
        with pytest.raises(PySnmpError):
            lcd.configure(manager, user(), StubTransportTarget())
        lcd.unconfigure(manager)
        assert all(not entries for entries in lcd._getCache(manager).values())
        with pytest.raises(NoSuchInstanceError):
            assertUser(manager, manager.snmpEngineID)


async def test_command_cleanup_preserves_a_trap_user_with_different_keys():
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        _, target = await startAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        assertDescription(await getDescription(manager, user(), target))
        notificationLcd.configure(manager, user("authpassword2"), target, "trap", b"")
        lcd.unconfigure(manager, user())
        assertUser(manager, manager.snmpEngineID)


@pytest.mark.parametrize("explicitFirst", (False, True))
async def test_inform_uses_the_latest_credentials_for_a_shared_target(explicitFirst):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        engineId = OctetString(hexValue="8000000001")
        agent, target = await startAgent(stack, engineId, "authpassword1")
        ntfrcv.NotificationReceiver(agent, lambda *args: None)
        profiles = [user(engineId=engineId), user()]
        if not explicitFirst:
            profiles.reverse()
        for authData in profiles:
            result = await request(manager, authData, target, "inform")
            assert result[0] is None, str(result[0])

        config.addV3User(agent, USER, usmHMAC192SHA256AuthProtocol, "authpassword2")
        profiles[1].authKey = "authpassword2"
        result = await request(manager, profiles[1], target, "inform")
        assert result[0] is None, str(result[0])


@pytest.mark.parametrize("mpModel", (0, 1), ids=("v1", "v2c"))
async def test_repeated_community_configuration_releases_all_targets(mpModel):
    async with SnmpEngine() as manager:
        authData = CommunityData("public", mpModel=mpModel)
        for port in (161, 162):
            target = StubTransportTarget()
            target.transportAddr = ("127.0.0.1", port)
            for _ in range(3):
                lcd.configure(manager, authData, target)
        addresses, params = lcd.unconfigure(manager, authData)
        assert len(addresses) == 2
        assert len(params) == 1
        assert config.getTransport(manager, target.transportDomain) is None
        assert all(not entries for entries in lcd._getCache(manager).values())


async def test_cleanup_preserves_a_transport_registered_by_the_caller():
    async with SnmpEngine() as manager:
        transport = udp.UdpTransport().openClientMode()
        config.addTransport(manager, udp.domainName, transport)
        lcd.configure(manager, user(), StubTransportTarget(), deferUsm=True)
        lcd.unconfigure(manager)
        assert config.getTransport(manager, udp.domainName) is transport


async def test_cleanup_after_target_configuration_fails(monkeypatch):
    async with SnmpEngine() as manager:
        failure = PySnmpError("Target registration failed")
        with monkeypatch.context() as patch:
            patch.setattr(config, "addTargetAddr", Mock(side_effect=failure))
            with pytest.raises(PySnmpError):
                lcd.configure(manager, user(), StubTransportTarget(), deferUsm=True)
        lcd.unconfigure(manager)
        assert all(not entries for entries in lcd._getCache(manager).values())
        assert config.getTransport(manager, udp.domainName) is None


@pytest.mark.parametrize("engineId", (b"x", b"x" * 33))
async def test_invalid_engine_id_does_not_leave_an_uncleanable_user(engineId):
    async with SnmpEngine() as manager:
        with pytest.raises(PyAsn1Error):
            lcd.configure(manager, user(engineId=engineId), StubTransportTarget())
        lcd.unconfigure(manager)
        assert all(not entries for entries in lcd._getCache(manager).values())
