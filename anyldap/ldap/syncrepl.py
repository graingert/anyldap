"""``ldap.syncrepl``: keeping a copy of what a server holds (RFC 4533).

A syncrepl search asks the server to say not only what matches now but what
changes afterwards. The server answers each entry with a Sync State control
saying whether it is present, added, changed or gone, says where it has got
to in Sync Info messages sent while the search runs, and finishes with a
Sync Done control carrying the cookie to start again from.

:class:`SyncreplConsumer` drives that: a connection mixes it in, overrides
the ``syncrepl_*`` methods to keep whatever copy it is keeping, and calls
``syncrepl_search()`` and then ``syncrepl_poll()`` until it answers False::

    class Consumer(SyncreplConsumer, ldap.SimpleLDAPObject):
        def syncrepl_entry(self, dn, attrs, uuid):
            self.entries[uuid] = (dn, attrs)

    async with Consumer(uri) as connection:
        await connection.simple_bind_s(who, cred)
        msgid = await connection.syncrepl_search(base, ldap.SCOPE_SUBTREE)
        while await connection.syncrepl_poll(msgid=msgid):
            pass

Only ``syncrepl_search()`` and ``syncrepl_poll()`` touch the connection and
are awaited; the methods a subclass overrides stay plain, as they are in
python-ldap, because they are called while a message is being dispatched.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any
from uuid import UUID

from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap._ber import elements
from anyldap.ldap.constants import (
    CONTROL_SYNC,
    CONTROL_SYNC_DONE,
    CONTROL_SYNC_STATE,
    RES_SEARCH_ENTRY,
    RES_SEARCH_RESULT,
    SCOPE_SUBTREE,
)
from anyldap.ldap.constants import RES_INTERMEDIATE as RES_INTERMEDIATE
from anyldap.ldap.controls import (
    KNOWN_RESPONSE_CONTROLS,
    RequestControl,
    ResponseControl,
)
from anyldap.protocols import pureber

__all__ = [
    "SyncRequestControl",
    "SyncStateControl",
    "SyncDoneControl",
    "SyncInfoMessage",
    "SyncreplConsumer",
]

# The OID of the Sync Info message, which is an intermediate response.
SYNC_INFO = "1.3.6.1.4.1.4203.1.9.1.4"

# Which mode a syncrepl search is in: stop once it has caught up, or stay
# open and keep being told. Two is reserved and zero is unused.
_MODES = {"refreshOnly": 1, "refreshAndPersist": 3}

# What a Sync Info message is saying, told by the tag it is written with.
_NEW_COOKIE = pureber.CLASS_CONTEXT | 0x00
_REFRESH_DELETE = pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x01
_REFRESH_PRESENT = pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x02
_SYNC_ID_SET = pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x03


def _uuid(raw: bytes) -> str:
    """An entry's UUID, written the way python-ldap writes it."""
    return str(UUID(bytes=raw))


def _cookie(raw: bytes) -> str:
    """A cookie, as text: python-ldap hands these back as str."""
    return to_unicode(raw)


class SyncRequestControl(RequestControl):
    """Ask a search to be a syncrepl search.

    ``mode`` is ``refreshOnly`` to be told what there is now and stop, or
    ``refreshAndPersist`` to be told about changes as they happen.
    ``cookie`` is where a previous search got to, and starting from it asks
    for what has changed since.
    """

    controlType = CONTROL_SYNC

    def __init__(
        self,
        criticality: bool = True,
        cookie: str | bytes | None = None,
        mode: str = "refreshOnly",
        reloadHint: bool = False,
    ) -> None:
        self.criticality = criticality
        self.cookie = cookie
        self.mode = mode
        self.reloadHint = reloadHint

    def encodeControlValue(self) -> bytes:
        if self.mode not in _MODES:
            raise ValueError(f"unknown syncrepl mode {self.mode!r}")
        value: list[pureber.BERBase] = [pureber.BEREnumerated(_MODES[self.mode])]
        if self.cookie is not None:
            value.append(pureber.BEROctetString(to_bytes(self.cookie)))
        if self.reloadHint:
            value.append(pureber.BERBoolean(1))
        return pureber.BERSequence(value).toWire()


class SyncStateControl(ResponseControl):
    """What has become of the entry the server just sent.

    It is present as it was, newly added, changed, or gone; the entry's UUID
    is what says which entry it is from one message to the next.
    """

    controlType = CONTROL_SYNC_STATE
    opnames = ("present", "add", "modify", "delete")

    def __init__(self, criticality: bool = False) -> None:
        ResponseControl.__init__(self, CONTROL_SYNC_STATE, criticality)
        self.state: str | None = None
        self.entryUUID: str | None = None
        self.cookie: str | None = None

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        [(_, content)] = elements(encodedControlValue)
        read = elements(content)
        self.state = self.opnames[pureber.ber2int(read[0][1])]
        self.entryUUID = _uuid(read[1][1])
        self.cookie = _cookie(read[2][1]) if len(read) > 2 else None


KNOWN_RESPONSE_CONTROLS[CONTROL_SYNC_STATE] = SyncStateControl


class SyncDoneControl(ResponseControl):
    """The end of a syncrepl search: where it got to, and what that means.

    ``refreshDeletes`` says whether the server named the entries that are
    gone, or whether whatever was not sent is what is gone.
    """

    controlType = CONTROL_SYNC_DONE

    def __init__(self, criticality: bool = False) -> None:
        ResponseControl.__init__(self, CONTROL_SYNC_DONE, criticality)
        self.cookie: str | None = None
        self.refreshDeletes: bool | None = None

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        [(_, content)] = elements(encodedControlValue)
        self.cookie = None
        self.refreshDeletes = None
        for tag, value in elements(content):
            if tag == pureber.BEROctetString.tag:
                self.cookie = _cookie(value)
            else:
                self.refreshDeletes = bool(value[0])


KNOWN_RESPONSE_CONTROLS[CONTROL_SYNC_DONE] = SyncDoneControl


class SyncInfoMessage:
    """What the server says while a syncrepl search is running.

    One of four things: a new cookie on its own, the end of the refresh
    phase with the entries that are gone named or not named, or a set of
    entries that are all present or all gone.
    """

    responseName = SYNC_INFO

    def __init__(self, encodedMessage: bytes) -> None:
        self.newcookie: str | None = None
        self.refreshDelete: dict[str, Any] | None = None
        self.refreshPresent: dict[str, Any] | None = None
        self.syncIdSet: dict[str, Any] | None = None

        [(tag, content)] = elements(encodedMessage)
        if tag == _NEW_COOKIE:
            self.newcookie = _cookie(content)
            return

        value: dict[str, Any] = {}
        read = elements(content)
        if read and read[0][0] == pureber.BEROctetString.tag:
            value["cookie"] = _cookie(read[0][1])
            read = read[1:]

        if tag in (_REFRESH_DELETE, _REFRESH_PRESENT):
            # refreshDone is TRUE unless the server said otherwise.
            value["refreshDone"] = bool(read[0][1][0]) if read else True
            if tag == _REFRESH_DELETE:
                self.refreshDelete = value
            else:
                self.refreshPresent = value
            return

        if tag != _SYNC_ID_SET:
            raise ValueError(f"unknown syncrepl info message {tag:#x}")
        # refreshDeletes is FALSE unless the server said otherwise, and the
        # UUIDs are the set that is always there.
        value["refreshDeletes"] = False
        if read[0][0] == pureber.BERBoolean.tag:
            value["refreshDeletes"] = bool(read[0][1][0])
            read = read[1:]
        value["syncUUIDs"] = [_uuid(raw) for _, raw in elements(read[0][1])]
        self.syncIdSet = value


if TYPE_CHECKING:  # pragma: no cover
    # What the mixin is mixed into, so that the calls below are checked
    # against the connection that will really answer them.
    from anyldap.ldap.ldapobject import SimpleLDAPObject as _MixedInto
else:
    _MixedInto = object


class SyncreplConsumer(_MixedInto):
    """A connection that keeps a copy of what the server holds.

    Only one syncrepl search can be running on one of these at a time; two
    at once need two connections, as they do in python-ldap.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__refreshDone = False

    async def syncrepl_search(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        mode: str = "refreshOnly",
        cookie: str | bytes | None = None,
        **search_args: Any,
    ) -> int:
        """Start the search, and answer with the message id it was sent as.

        ``base``, ``scope`` and the rest are ``search_ext()``'s, with the
        Sync Request control added to whatever controls were given. The
        cookie is asked of ``syncrepl_get_cookie()`` if it is not passed.
        """
        if cookie is None:
            cookie = self.syncrepl_get_cookie()
        syncreq = SyncRequestControl(cookie=cookie, mode=mode)
        if "serverctrls" in search_args:
            search_args["serverctrls"] = list(search_args["serverctrls"]) + [syncreq]
        else:
            search_args["serverctrls"] = [syncreq]
        self.__refreshDone = False
        return await self.search_ext(base, scope, **search_args)

    async def syncrepl_poll(
        self, msgid: int = -1, timeout: float | None = None, all: int = 0
    ) -> bool:
        """Read what the search has said, and hand it on.

        Answers False once the search is finished and True while it is still
        running. With ``all`` set it reads until the search finishes rather
        than returning after one message.
        """
        while True:
            rtype, msg, _, ctrls, _, _ = await self.result4(
                msgid=msgid,
                timeout=timeout,
                add_intermediates=1,
                add_ctrls=1,
                all=0,
            )

            if rtype == RES_SEARCH_RESULT:
                # The end of a refreshOnly search: what the Sync Done
                # control says is where to start again from, and whether
                # what was not sent is what is gone.
                for control in ctrls:
                    if not isinstance(control, SyncDoneControl):
                        continue
                    self.syncrepl_present(None, refreshDeletes=control.refreshDeletes)
                    if control.cookie is not None:
                        self.syncrepl_set_cookie(control.cookie)
                return False

            if rtype == RES_SEARCH_ENTRY:
                for item in msg:
                    dn, attrs, entry_controls = item  # type: ignore[misc]
                    for control in entry_controls:
                        if not isinstance(control, SyncStateControl):
                            continue
                        assert control.entryUUID is not None
                        if control.state == "present":
                            self.syncrepl_present([control.entryUUID])
                        elif control.state == "delete":
                            self.syncrepl_delete([control.entryUUID])
                        else:
                            assert isinstance(dn, str) and isinstance(attrs, dict)
                            self.syncrepl_entry(dn, attrs, control.entryUUID)
                            if self.__refreshDone is False:
                                self.syncrepl_present([control.entryUUID])
                        if control.cookie is not None:
                            self.syncrepl_set_cookie(control.cookie)
                        break

            else:
                # Something the server said while the search runs, which is
                # a Sync Info message if it is about the search at all.
                for item in msg:
                    rname, response, _ = item  # type: ignore[misc]
                    if rname != SyncInfoMessage.responseName:
                        continue
                    assert isinstance(response, bytes)
                    self._syncrepl_info(SyncInfoMessage(response))

            if all == 0:
                return True

    def _syncrepl_info(self, message: SyncInfoMessage) -> None:
        """What one Sync Info message means for the copy being kept."""
        if message.newcookie is not None:
            self.syncrepl_set_cookie(message.newcookie)
        elif message.refreshPresent is not None:
            self.syncrepl_present(None, refreshDeletes=False)
            self._syncrepl_refresh(message.refreshPresent)
        elif message.refreshDelete is not None:
            self.syncrepl_present(None, refreshDeletes=True)
            self._syncrepl_refresh(message.refreshDelete)
        else:
            assert message.syncIdSet is not None
            if message.syncIdSet["refreshDeletes"] is True:
                self.syncrepl_delete(message.syncIdSet["syncUUIDs"])
            else:
                self.syncrepl_present(message.syncIdSet["syncUUIDs"])
            if "cookie" in message.syncIdSet:
                self.syncrepl_set_cookie(message.syncIdSet["cookie"])

    def _syncrepl_refresh(self, said: dict[str, Any]) -> None:
        if "cookie" in said:
            self.syncrepl_set_cookie(said["cookie"])
        if said["refreshDone"]:
            self.__refreshDone = True
            self.syncrepl_refreshdone()

    # The methods a subclass overrides to keep whatever it is keeping.

    def syncrepl_set_cookie(self, cookie: str) -> None:
        """Store a new cookie, which says where the search has got to."""

    def syncrepl_get_cookie(self) -> str | bytes | None:
        """The cookie that was stored, to start the next search from."""
        return None

    def syncrepl_present(
        self, uuids: Sequence[str] | None, refreshDeletes: bool | None = False
    ) -> None:
        """These entries are still there, or the refresh has finished.

        Given a list of UUIDs, record them as present. Given None and
        ``refreshDeletes`` false, delete everything that was not recorded
        and start the record again; given None and ``refreshDeletes`` true,
        start the record again without deleting anything.
        """

    def syncrepl_delete(self, uuids: Sequence[str]) -> None:
        """These entries are gone."""

    def syncrepl_entry(
        self, dn: str, attrs: dict[str, list[bytes]], uuid: str
    ) -> None:
        """This entry was added or changed, and this is what it is now."""

    def syncrepl_refreshdone(self) -> None:
        """The refresh is over, and what follows is what changes next."""
