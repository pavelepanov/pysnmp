#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
#
"""Turning high-level credentials into the engine's own configuration.

The local configuration datastore is what the engine actually reads. These
configurators write `CommunityData` and `UsmUserData` into it, and cache what
they wrote so repeating a call does not re-register anything.
"""

from copy import copy
from functools import partial
from typing import Any

from pysnmp import error, nextid
from pysnmp.entity import config
from pysnmp.hlapi.auth import CommunityData, UsmUserData
from pysnmp.proto.rfc1902 import OctetString

__all__ = ["CommandGeneratorLcdConfigurator", "NotificationOriginatorLcdConfigurator"]

#: The finest resolution AbstractTransportDispatcher.setTimerResolution()
#: accepts. Mirrored rather than imported so lowering the clock cannot raise
#: out of configure() for a caller who merely asked for a small timeout.
MIN_TIMER_RESOLUTION = 0.01

#: What makes two `UsmUserData` the same *credentials*, rather than merely the
#: same user. The cache is keyed on the user name and security engine ID, which
#: say which USM row is being configured but nothing about what is in it, so
#: these are compared separately before a cached row is reused.
#:
#: The key types are in the list because they decide how the key is read -- a
#: passphrase and a pre-localized key of the same bytes are different
#: credentials -- and `securityName` because it is what the row maps the user
#: on to.
USM_CREDENTIAL_ATTRIBUTES = (
    "authProtocol",
    "authKey",
    "authKeyType",
    "privProtocol",
    "privKey",
    "privKeyType",
    "securityName",
)


def _usmCredentialsDiffer(cached, incoming):
    """Whether these two `UsmUserData` would configure the USM row differently."""
    return any(
        getattr(cached, attribute, None) != getattr(incoming, attribute, None)
        for attribute in USM_CREDENTIAL_ATTRIBUTES
    )


def _usmKeyId(authData):
    """Key derivation depends on the protocols, key bytes and key types."""
    return (
        authData.authProtocol,
        OctetString(authData.authKey or b"").asOctets(),
        authData.authKeyType,
        authData.privProtocol,
        OctetString(authData.privKey or b"").asOctets(),
        authData.privKeyType,
    )


#: How many dispatcher ticks a request timeout should span.
#:
#: Expiry is counted in ticks, not seconds, so a timeout finer than one tick
#: cannot be measured at all. Two is what the stock pairing already gives -- a
#: 1 second timeout against the default 0.5 second resolution -- so requiring
#: the same of a finer timeout keeps its precision the same rather than making
#: it better than the default's.
TICKS_PER_TIMEOUT = 2


def _alignTimerResolution(snmpEngine, timeout):
    """Make the dispatcher's clock fine enough to measure *timeout* seconds.

    A target's timeout is stored faithfully, in centiseconds, and then expires
    on a clock that ticks once per the dispatcher's timer resolution -- 0.5
    seconds by default. So `UdpTransportTarget(addr, timeout=0.2)` was accepted,
    reported back by __repr__, and then rounded up to the next tick by the thing
    that acts on it. Sub-second timeouts are the normal ask for polling a large
    estate on a LAN, where that floor sets the pace of the whole run.

    The resolution is dispatcher-wide while timeouts are per-target, so this
    only ever lowers it: fine enough for the finest target that has been
    configured, and never coarser than it already was. It stays inside the
    dispatcher's own 10ms floor, since the tick drives a periodic callback whose
    cost is not free -- a timeout below that is still honoured as well as the
    clock allows rather than being refused.
    """
    dispatcher = snmpEngine.transportDispatcher

    if dispatcher is None or not timeout:
        return

    required = float(timeout) / TICKS_PER_TIMEOUT

    if required >= dispatcher.getTimerResolution():
        return

    dispatcher.setTimerResolution(max(required, MIN_TIMER_RESOLUTION))


class AbstractLcdConfigurator:
    nextID = nextid.Integer(0xFFFFFFFF)
    #: Sections _getCache() lays out in this configurator's user context.
    cacheKeys: list[str] = []

    def _getCache(self, snmpEngine):
        """The cache this configurator keeps on the engine, created on first use."""
        cacheId = self.__class__.__name__
        cache = snmpEngine.getUserContext(cacheId)
        if cache is None:
            cache = {x: {} for x in self.cacheKeys}
            snmpEngine.setUserContext(**{cacheId: cache})
        return cache

    def configure(self, snmpEngine, *args, **kwargs):
        """Write configuration to the engine. Subclasses implement this."""
        # Subclasses provide protocol-specific configuration.
        pass

    def unconfigure(self, snmpEngine, *args, **kwargs):
        """Take configuration back out. Subclasses implement this."""
        # Subclasses provide protocol-specific cleanup.
        pass


class CommandGeneratorLcdConfigurator(AbstractLcdConfigurator):
    """Configures the engine to send requests, and tears that down again.

    Target rows are shared by configurations. Removing a configuration releases
    its targets and users while retaining rows used by other configurations.
    """

    # usm stores (credentials, owning configurations) for each actual user row.
    # bindings links each configuration to its target rows; keys shares
    # master keys across peers with identical credentials.
    cacheKeys = ["auth", "usm", "keys", "bindings", "parm", "tran", "addr"]

    def _masterKeys(self, snmpEngine, authData):
        """Hash a passphrase once; localizing that master key is cheap per peer."""
        keys = self._getCache(snmpEngine)["keys"]
        keyId = _usmKeyId(authData)
        if keyId not in keys:
            user = copy(authData)
            if user.authKeyType == config.usmKeyTypePassphrase:
                user.authKey = config.authServices[user.authProtocol].hashPassphrase(
                    user.authKey or b""
                )
                user.authKeyType = config.usmKeyTypeMaster
            if user.privKeyType == config.usmKeyTypePassphrase:
                user.privKey = config.privServices[user.privProtocol].hashPassphrase(
                    user.authProtocol, user.privKey or b""
                )
                user.privKeyType = config.usmKeyTypeMaster
            keys[keyId] = user
        return keys[keyId]

    def _configureUsmUser(
        self,
        snmpEngine,
        transportDomain=None,
        transportAddress=None,
        *,
        authData,
        authDataKey,
    ):
        """Register credentials for an explicit engine ID or a discovered peer."""
        authData = copy(authData)
        if transportDomain is not None and (
            authData.securityEngineId is None
            or OctetString(authData.securityEngineId)
            == OctetString(hexValue="0000000000")
        ):
            model = snmpEngine.messageProcessingSubsystems[authData.mpModel]
            authData.securityEngineId, _, _ = model.getPeerEngineInfo(
                transportDomain, transportAddress
            )
            if authData.securityEngineId is None:
                return  # Discovery sends without a user; the retry registers it.

        users = self._getCache(snmpEngine)["usm"]
        userKey = (
            authData.userName,
            OctetString(authData.securityEngineId)
            if authData.securityEngineId is not None
            else snmpEngine.snmpEngineID,
        )
        cached, owners = users.get(userKey, (None, set()))
        if cached is not None and not _usmCredentialsDiffer(cached, authData):
            owners.add(authDataKey)
            return

        keys = self._masterKeys(snmpEngine, authData)
        owners.add(authDataKey)
        # A failed write must not leave the old credentials marked as installed.
        # Keep ownership so cleanup also removes a partially written row.
        users[userKey] = None, owners
        if cached is not None:
            # Password rotation only removes this engine's user and its clones.
            config.delV3User(snmpEngine, *userKey)

        config.addV3User(
            snmpEngine,
            authData.userName,
            authData.authProtocol,
            keys.authKey,
            authData.privProtocol,
            keys.privKey,
            securityEngineId=authData.securityEngineId,
            securityName=authData.securityName,
            authKeyType=keys.authKeyType,
            privKeyType=keys.privKeyType,
        )
        users[userKey] = copy(authData), owners

    def getUserCallback(self, authData, transportTarget):
        """Bind this request's credential snapshot to the user registration method."""
        if not isinstance(authData, UsmUserData):
            return None
        authDataKey = (
            authData.userName,
            authData.securityEngineId,
            transportTarget.transportDomain,
            transportTarget.transportAddr,
        )
        return partial(
            self._configureUsmUser, authData=copy(authData), authDataKey=authDataKey
        )

    def configure(
        self, snmpEngine, authData, transportTarget, contextName=b"", **options
    ):
        """Write the rows a request needs; repeated configuration reuses them."""
        cache = self._getCache(snmpEngine)
        authDataKey: Any
        if isinstance(authData, CommunityData):
            authDataKey = authData.communityIndex
            if authData.communityIndex not in cache["auth"]:
                config.addV1System(
                    snmpEngine,
                    authData.communityIndex,
                    authData.communityName,
                    authData.contextEngineId,
                    authData.contextName,
                    authData.tag,
                    authData.securityName,
                )
                cache["auth"][authData.communityIndex] = authData
        elif isinstance(authData, UsmUserData):
            config._checkV3Protocols(authData.authProtocol, authData.privProtocol)
            # Validate MIB syntax now, so configuration errors reach the caller
            # before a discovery retry runs inside the dispatcher callback.
            mibBuilder = snmpEngine.getMibBuilder()
            userName, securityName, engineId = mibBuilder.importSymbols(
                "SNMP-USER-BASED-SM-MIB",
                "usmUserName",
                "usmUserSecurityName",
                "usmUserEngineID",
            )
            (keyType,) = mibBuilder.importSymbols(
                "__PYSNMP-USM-MIB", "pysnmpUsmKeyType"
            )
            userName.syntax.clone(authData.userName)
            securityName.syntax.clone(authData.securityName)
            if authData.securityEngineId is not None:
                engineId.syntax.clone(authData.securityEngineId)
            keyType.syntax.clone(authData.authKeyType)
            keyType.syntax.clone(authData.privKeyType)
            authDataKey = authData.userName, authData.securityEngineId
            if options.get("deferUsm", False):
                # Retain configuration per target while its engine ID is unknown.
                # The request callback registers the USM row before sending.
                authDataKey += (
                    transportTarget.transportDomain,
                    transportTarget.transportAddr,
                )
            cached = cache["auth"].get(authDataKey)
            if cached is not None and _usmCredentialsDiffer(cached, authData):
                cache["keys"].pop(_usmKeyId(cached), None)
            if not options.get("deferUsm", False):
                self._configureUsmUser(
                    snmpEngine, authData=authData, authDataKey=authDataKey
                )
            else:
                self._masterKeys(snmpEngine, authData)
            # Keep the most recently configured profile last. A target can be
            # shared by an explicit-ID profile and one using discovery.
            cache["auth"].pop(authDataKey, None)
            cache["auth"][authDataKey] = copy(authData)
        else:
            raise error.PySnmpError("Unsupported authentication object")

        paramsKey = (authData.securityName, authData.securityLevel, authData.mpModel)
        if paramsKey in cache["parm"]:
            paramsName = cache["parm"][paramsKey]
        else:
            paramsName = f"p{self.nextID()}"
            config.addTargetParams(
                snmpEngine,
                paramsName,
                authData.securityName,
                authData.securityLevel,
                authData.mpModel,
            )
            cache["parm"][paramsKey] = paramsName

        if config.getTransport(snmpEngine, transportTarget.transportDomain):
            transportTarget.verifyDispatcherCompatibility(snmpEngine)
        else:
            transport = transportTarget.openClientMode()
            config.addTransport(snmpEngine, transportTarget.transportDomain, transport)
            cache["tran"][transportTarget.transportDomain] = transport

        _alignTimerResolution(snmpEngine, transportTarget.timeout)

        transportKey = (
            paramsName,
            transportTarget.transportDomain,
            transportTarget.transportAddr,
            transportTarget.timeout,
            transportTarget.retries,
            transportTarget.tagList,
            transportTarget.iface,
        )

        if transportKey in cache["addr"]:
            addrName = cache["addr"][transportKey]
        else:
            addrName = f"a{self.nextID()}"
            config.addTargetAddr(
                snmpEngine,
                addrName,
                transportTarget.transportDomain,
                transportTarget.transportAddr,
                paramsName,
                transportTarget.timeout * 100,
                transportTarget.retries,
                transportTarget.tagList,
            )
            cache["addr"][transportKey] = addrName

        cache["bindings"].setdefault(authDataKey, set()).add(transportKey)
        return addrName, paramsName

    def unconfigure(self, snmpEngine, authData=None, contextName=b"", **options):
        """Remove matching credentials and their targets, or everything with no credentials."""
        cache = self._getCache(snmpEngine)
        if authData is None:
            authDataKeys = tuple(cache["auth"])
        elif isinstance(authData, CommunityData):
            authDataKeys = tuple(
                key for key in cache["auth"] if key == authData.communityIndex
            )
        elif isinstance(authData, UsmUserData):
            authDataKeys = tuple(
                key
                for key, cached in cache["auth"].items()
                if isinstance(cached, UsmUserData)
                and cached.userName == authData.userName
                and cached.securityEngineId == authData.securityEngineId
                and not _usmCredentialsDiffer(cached, authData)
            )
        else:
            raise error.PySnmpError("Unsupported authentication object")
        if authData is not None and not authDataKeys:
            raise error.PySnmpError(f"Unknown authData {authData}")

        addrNames, paramsNames = set(), set()

        # A discovered and an explicit-ID configuration may own the same row.
        # None in the original configuration is not a wildcard for all peers.
        for userKey, (_, owners) in tuple(cache["usm"].items()):
            if authData is None:
                # Include rows whose initial registration failed before the
                # rest of their target configuration could be cached.
                owners.clear()
            else:
                owners.difference_update(authDataKeys)
            if not owners:
                config.delV3User(snmpEngine, *userKey)
                del cache["usm"][userKey]

        for authDataKey in authDataKeys:
            authDataX = cache["auth"][authDataKey]
            del cache["auth"][authDataKey]
            if isinstance(authDataX, CommunityData):
                config.delV1System(snmpEngine, authDataX.communityIndex)
            elif not isinstance(authDataX, UsmUserData):
                raise error.PySnmpError("Unsupported authentication object")

            cache["bindings"].pop(authDataKey, None)

        # Keep exactly the targets referenced by the remaining configurations.
        activeAddresses = set().union(*cache["bindings"].values())
        for addrKey in cache["addr"].keys() - activeAddresses:
            config.delTargetAddr(snmpEngine, cache["addr"].pop(addrKey))
            addrNames.add(addrKey)

        activeParams = {key[0] for key in activeAddresses}
        for paramsKey, paramsName in tuple(cache["parm"].items()):
            if paramsName not in activeParams:
                config.delTargetParams(snmpEngine, cache["parm"].pop(paramsKey))
                paramsNames.add(paramsName)

        activeDomains = {key[1] for key in activeAddresses}
        for domain in cache["tran"].keys() - activeDomains:
            config.delTransport(snmpEngine, domain)
            cache["tran"].pop(domain).closeTransport()

        activeKeys = {
            _usmKeyId(user)
            for user in cache["auth"].values()
            if isinstance(user, UsmUserData)
        }
        for keyId in tuple(cache["keys"]):
            if keyId not in activeKeys:
                del cache["keys"][keyId]

        return addrNames, paramsNames


class NotificationOriginatorLcdConfigurator(AbstractLcdConfigurator):
    """Configures the engine to send notifications, and tears that down again.

    Builds on the command generator's configuration, since a notification still
    needs a target and credentials, and adds the notification and filter rows on
    top.
    """

    cacheKeys = ["auth", "name"]
    _cmdGenLcdCfg = CommandGeneratorLcdConfigurator()

    def getTargetUserCallback(self, snmpEngine, targetName):
        """Snapshot the selected receiver's credentials, including tag fanout."""
        cache = self._cmdGenLcdCfg._getCache(snmpEngine)
        targetName = OctetString(targetName)
        for authDataKey in reversed(cache["auth"]):
            authData = cache["auth"][authDataKey]
            if not isinstance(authData, UsmUserData):
                continue
            bindings = cache["bindings"].get(authDataKey, ())
            if any(OctetString(cache["addr"][key]) == targetName for key in bindings):
                return partial(
                    self._cmdGenLcdCfg._configureUsmUser,
                    authData=copy(authData),
                    authDataKey=authDataKey,
                )
        # A target configured through the entity API already has its USM user.
        return None

    def configure(
        self, snmpEngine, authData, transportTarget, notifyType, contextName, **options
    ):
        """Write the rows a notification needs, including its notify tag."""
        cache = self._getCache(snmpEngine)
        notifyName = None

        # Create matching transport tags if not given by user. Not good!
        if not transportTarget.tagList:
            transportTarget.tagList = str(
                hash((authData.securityName, transportTarget.transportAddr))
            )
        if isinstance(authData, CommunityData) and not authData.tag:
            authData.tag = transportTarget.tagList.split()[0]

        addrName, paramsName = self._cmdGenLcdCfg.configure(
            snmpEngine, authData, transportTarget, contextName, **options
        )
        tagList = transportTarget.tagList.split()
        if not tagList:
            tagList = [""]
        for tag in tagList:
            notifyNameKey = paramsName, tag, notifyType
            if notifyNameKey in cache["name"]:
                notifyName, paramsName = cache["name"][notifyNameKey]
            else:
                notifyName = f"n{self.nextID()}"
                config.addNotificationTarget(
                    snmpEngine, notifyName, paramsName, tag, notifyType
                )
                cache["name"][notifyNameKey] = notifyName, paramsName
        authDataKey = (
            authData.securityName,
            authData.securityModel,
            authData.securityLevel,
            contextName,
        )
        if authDataKey not in cache["auth"]:
            subTree = (1, 3, 6)
            config.addTrapUser(
                snmpEngine,
                authData.securityModel,
                authData.securityName,
                authData.securityLevel,
                subTree,
                contextName=contextName,
            )
            cache["auth"][authDataKey] = copy(authData), subTree

        return notifyName

    def unconfigure(self, snmpEngine, authData=None, contextName=b"", **options):
        """Remove those rows once nothing is using them."""
        cache = self._getCache(snmpEngine)
        if authData:
            authDataKey = (
                authData.securityName,
                authData.securityModel,
                authData.securityLevel,
                contextName,
            )
            if authDataKey in cache["auth"]:
                authDataKeys = (authDataKey,)
            else:
                raise error.PySnmpError(f"Unknown authData {authData}")
        else:
            authDataKeys = tuple(cache["auth"])

        addrNames, paramsNames = self._cmdGenLcdCfg.unconfigure(
            snmpEngine, authData, contextName, **options
        )

        notifyAndParamsNames = [
            (cache["name"][x], x) for x in cache["name"] if x[0] in paramsNames
        ]

        for (notifyName, paramsName), notifyNameKey in notifyAndParamsNames:
            config.delNotificationTarget(snmpEngine, notifyName, paramsName)
            del cache["name"][notifyNameKey]

        commandCache = self._cmdGenLcdCfg._getCache(snmpEngine)
        for authDataKey in authDataKeys:
            authDataX, subTree = cache["auth"][authDataKey]
            paramsKey = (
                authDataX.securityName,
                authDataX.securityLevel,
                authDataX.mpModel,
            )
            if paramsKey not in commandCache["parm"]:
                config.delTrapUser(
                    snmpEngine,
                    authDataX.securityModel,
                    authDataX.securityName,
                    authDataX.securityLevel,
                    subTree,
                    contextName=authDataKey[3],
                )
                del cache["auth"][authDataKey]
