"""One manager must retain each peer's credentials across discovery and replies."""

import asyncio
from contextlib import AsyncExitStack

import pytest

from pysnmp.entity import config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.error import PySnmpError
from pysnmp.hlapi.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UsmUserData,
    bulk_cmd,
    next_cmd,
    send_notification,
    set_cmd,
    usmAesCfb128Protocol,
    usmHMAC192SHA256AuthProtocol,
)
from pysnmp.hlapi.asyncio.cmdgen import lcd
from pysnmp.hlapi.auth import usmKeyTypeLocalized, usmKeyTypeMaster
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.smi.error import NoSuchInstanceError
from tests.end_to_end import COLD_START, SNMP_TRAP_OID, SYS_DESCR
from tests.test_usm_user_identity import (
    USER,
    assertDescription,
    createAgent,
    getDescription,
    startAgent,
)


@pytest.mark.parametrize("credentials", ("authentication", "privacy", "security-name"))
@pytest.mark.parametrize("explicitId", (False, True), ids=("discovery", "known-id"))
async def test_concurrent_peers_keep_their_credentials(credentials, explicitId):
    """Repeat after discovery too: changing a template used to delete peer rows."""
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        requests = []
        for number in (1, 2):
            engineId = OctetString(hexValue=f"800000000{number}")
            authKey = f"authpassword{number if credentials == 'authentication' else 1}"
            privKey = f"privpassword{number}" if credentials == "privacy" else None
            target = await createAgent(stack, engineId, authKey, privKey)
            authData = UsmUserData(
                USER,
                authKey,
                privKey,
                authProtocol=usmHMAC192SHA256AuthProtocol,
                privProtocol=usmAesCfb128Protocol,
                securityEngineId=engineId if explicitId else None,
                securityName=f"device-{number}"
                if credentials == "security-name"
                else None,
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


async def test_identical_credentials_can_poll_many_peers(monkeypatch):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        authData = UsmUserData(
            USER,
            "authpassword1",
            "privpassword1",
            authProtocol=usmHMAC192SHA256AuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        targets = [
            await createAgent(
                stack,
                OctetString(hexValue=f"80000000{number:02x}"),
                "authpassword1",
                "privpassword1",
            )
            for number in range(1, 13)
        ]
        hashCalls = []
        hashPassphrase = localkey.hashPassphrase

        def countHash(*args):
            hashCalls.append(args)
            return hashPassphrase(*args)

        monkeypatch.setattr(localkey, "hashPassphrase", countHash)
        for _ in range(2):
            for result in await asyncio.gather(
                *(getDescription(manager, authData, target) for target in targets)
            ):
                assertDescription(result)
        # Hashing processes 1 MiB per passphrase. Do it once for each of the
        # authentication and privacy passphrases, rather than once per device.
        assert len(hashCalls) == 2


async def test_another_peer_does_not_invalidate_an_in_flight_reply(monkeypatch):
    """Hold A's authenticated reply until B has registered different credentials."""
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        targetA = await createAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        targetB = await createAgent(
            stack, OctetString(hexValue="8000000002"), "authpassword2"
        )
        authA = UsmUserData(
            USER, "authpassword1", authProtocol=usmHMAC192SHA256AuthProtocol
        )
        authB = UsmUserData(
            USER, "authpassword2", authProtocol=usmHMAC192SHA256AuthProtocol
        )
        assertDescription(await getDescription(manager, authA, targetA))

        transport = manager.transportDispatcher.getTransport(targetA.transportDomain)
        receive = transport._cbFun
        responseReady = asyncio.Event()
        held = []

        def holdResponse(transport, address, message):
            if address == targetA.transportAddr:
                held.append((transport, address, message))
                responseReady.set()
            else:
                receive(transport, address, message)

        monkeypatch.setattr(transport, "_cbFun", holdResponse)
        requestA = asyncio.create_task(getDescription(manager, authA, targetA))
        await asyncio.wait_for(responseReady.wait(), timeout=2)
        assertDescription(await getDescription(manager, authB, targetB))
        for response in held:
            receive(*response)
        assertDescription(await requestA)


@pytest.mark.parametrize("operation", ("next", "bulk", "set"))
async def test_other_commands_keep_their_credentials(operation):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())

        async def request(number):
            target = await createAgent(
                stack,
                OctetString(hexValue=f"800000000{number}"),
                f"authpassword{number}",
            )
            authData = UsmUserData(
                USER, f"authpassword{number}", authProtocol=usmHMAC192SHA256AuthProtocol
            )
            args = (manager, authData, target, ContextData())
            if operation == "set":
                result = await set_cmd(
                    *args,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1.6.0"), f"device-{number}"),
                )
                assert result[0] is None, str(result[0])
                assert not result[1]
                assert result[3][0][1].prettyPrint() == f"device-{number}"
            else:
                varBind = ObjectType(ObjectIdentity(SYS_DESCR.rsplit(".", 1)[0]))
                result = await (
                    next_cmd(*args, varBind)
                    if operation == "next"
                    else bulk_cmd(*args, 0, 1, varBind)
                )
                assertDescription((*result[:3], result[3][0] if result[3] else ()))

        await asyncio.wait_for(asyncio.gather(request(1), request(2)), timeout=5)


async def test_informs_keep_each_receivers_credentials():
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        requests = []
        received = []
        for number in (1, 2):
            agent, target = await startAgent(
                stack,
                OctetString(hexValue=f"800000000{number}"),
                f"authpassword{number}",
            )
            ntfrcv.NotificationReceiver(agent, lambda *args: received.append(args))
            authData = UsmUserData(
                USER, f"authpassword{number}", authProtocol=usmHMAC192SHA256AuthProtocol
            )
            requests.append((authData, target))
        for _ in range(2):
            results = await asyncio.wait_for(
                asyncio.gather(
                    *(
                        send_notification(
                            manager,
                            authData,
                            target,
                            ContextData(),
                            "inform",
                            [ObjectType(ObjectIdentity(SNMP_TRAP_OID), COLD_START)],
                        )
                        for authData, target in requests
                    )
                ),
                timeout=5,
            )
            for result in results:
                assert result[0] is None, str(result[0])
                assert not result[1]
        assert len(received) == 4


async def test_password_rotation_keeps_another_peers_keys():
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        engineId = OctetString(hexValue="8000000001")
        agentA, targetA = await startAgent(stack, engineId, "authpassword1")
        targetB = await createAgent(
            stack, OctetString(hexValue="8000000002"), "authpassword1"
        )
        authData = UsmUserData(
            USER, "authpassword1", authProtocol=usmHMAC192SHA256AuthProtocol
        )
        for result in await asyncio.gather(
            getDescription(manager, authData, targetA),
            getDescription(manager, authData, targetB),
        ):
            assertDescription(result)

        config.addV3User(agentA, USER, usmHMAC192SHA256AuthProtocol, "authpassword2")
        authData.authKey = "authpassword2"
        assertDescription(await getDescription(manager, authData, targetA))
        authB = UsmUserData(
            USER, "authpassword1", authProtocol=usmHMAC192SHA256AuthProtocol
        )
        assertDescription(await getDescription(manager, authB, targetB))


@pytest.mark.parametrize("discover", (False, True))
async def test_unconfigure_removes_users_and_targets(discover):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        for number in (1, 2):
            target = await createAgent(
                stack,
                OctetString(hexValue=f"800000000{number}"),
                f"authpassword{number}",
            )
            authData = UsmUserData(
                USER, f"authpassword{number}", authProtocol=usmHMAC192SHA256AuthProtocol
            )
            if discover:
                assertDescription(await getDescription(manager, authData, target))
            else:
                lcd.configure(manager, authData, target, deferUsm=True)

        lcd.unconfigure(manager)
        (entry,) = manager.getMibBuilder().importSymbols(
            "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
        )
        names = entry.getNode(entry.name + (2,))
        with pytest.raises(NoSuchInstanceError):
            names.getNextNode(names.name)
        assert config.getTransport(manager, target.transportDomain) is None


@pytest.mark.parametrize("keyType", ("no-auth", "master", "localized", "wildcard"))
async def test_key_types_work_with_a_shared_engine(keyType):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        requests = []
        for number in (1, 2):
            engineId = OctetString(hexValue=f"800000000{number}")
            password = f"authpassword{number}"
            agent, target = await startAgent(stack, engineId, password)
            if keyType == "no-auth":
                config.addV3User(agent, USER)
                config.addVacmUser(agent, 3, USER, "noAuthNoPriv", (1, 3, 6, 1, 2, 1))
                authData = UsmUserData(USER)
            else:
                service = config.authServices[usmHMAC192SHA256AuthProtocol]
                key = service.hashPassphrase(password)
                localized = keyType in ("localized", "wildcard")
                if localized:
                    key = service.localizeKey(key, engineId)
                authData = UsmUserData(
                    USER,
                    key,
                    authProtocol=usmHMAC192SHA256AuthProtocol,
                    authKeyType=usmKeyTypeLocalized if localized else usmKeyTypeMaster,
                    securityEngineId=(
                        OctetString(hexValue="0000000000")
                        if keyType == "wildcard"
                        else engineId
                        if localized
                        else None
                    ),
                )
            requests.append((authData, target))
        for result in await asyncio.gather(
            *(
                getDescription(manager, authData, target)
                for authData, target in requests
            )
        ):
            assertDescription(result)


@pytest.mark.parametrize("invalid", ("authentication", "privacy", "backend"))
async def test_configuration_errors_are_reported_before_discovery(invalid, monkeypatch):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        target = await createAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        authData = UsmUserData(
            USER,
            "authpassword1",
            "privpassword1",
            authProtocol=usmHMAC192SHA256AuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        if invalid == "authentication":
            authData.authProtocol = (9, 9, 9)
            message = "Unknown auth protocol"
        elif invalid == "privacy":
            authData.privProtocol = (9, 9, 9)
            message = "Unknown privacy protocol"
        else:
            monkeypatch.setattr(config.cipherbackend, "isAvailable", lambda: False)
            message = "privacy requires"
        with pytest.raises(PySnmpError, match=message):
            await getDescription(manager, authData, target)


async def test_request_credentials_are_a_snapshot_during_discovery(monkeypatch):
    async with AsyncExitStack() as stack:
        manager = await stack.enter_async_context(SnmpEngine())
        target = await createAgent(
            stack, OctetString(hexValue="8000000001"), "authpassword1"
        )
        authData = UsmUserData(
            USER, "authpassword1", authProtocol=usmHMAC192SHA256AuthProtocol
        )
        # Configure only the transport so the first discovery report can be held.
        lcd.configure(manager, authData, target, deferUsm=True)
        transport = manager.transportDispatcher.getTransport(target.transportDomain)
        receive = transport._cbFun
        responseReady = asyncio.Event()
        held = []

        def holdResponse(*args):
            held.append(args)
            responseReady.set()

        monkeypatch.setattr(transport, "_cbFun", holdResponse)
        request = asyncio.create_task(getDescription(manager, authData, target))
        await asyncio.wait_for(responseReady.wait(), timeout=2)
        authData.authKey = "authpassword2"
        monkeypatch.setattr(transport, "_cbFun", receive)
        for response in held:
            receive(*response)
        assertDescription(await request)
