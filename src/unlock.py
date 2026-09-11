"""Root-only unlock socket: how a systemd daemon is handed the global password.

No tty, no file, no TPM. A console prompt cannot be answered on a headless box,
and anything on disk that becomes the key defeats the point of the store. So the
daemon starts *locked* and completely inert - the Slack tokens are themselves
inside the encrypted store, so it cannot even connect - and becomes live when an
administrator runs `hoisty unlock` on the machine. The passphrase crosses a unix
socket in /run, is turned into a key, and is wiped.

Only uid 0 may drive the socket. The file mode already limits it to the daemon's
own uid, but a playbook that has gone bad runs as that uid, so the peer's
credentials are checked as well (SO_PEERCRED cannot be forged: the kernel fills
it in).
"""
import contextlib
import logging
import os
import socket
import struct
import threading
from pathlib import Path

import db

logger = logging.getLogger(__name__)

SOCKET = Path(os.environ.get('HOISTY_RUNTIME') or '/run/hoisty') / 'unlock.sock'
MAX_LINE = 4096
ROOT_ONLY = (0,)


def sd_notify(state):
    """Tell systemd what we are doing, so `systemctl status` says "locked"
    instead of leaving an operator guessing. A no-op when not under systemd."""
    address = os.environ.get('NOTIFY_SOCKET')
    if not address:
        return
    if address.startswith('@'):           # abstract namespace
        address = '\0' + address[1:]
    with contextlib.suppress(OSError):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(state.encode())


class Gate:
    """Holds the store once someone unlocks it; the daemon waits on `ready`."""

    def __init__(self):
        self._lock = threading.Lock()
        self.store = None
        self.ready = threading.Event()

    def unlock(self, passphrase):
        """None on success, else a message for the client. Never echoes the
        passphrase: db.Locked's text is fixed, not derived from the input."""
        with self._lock:
            if self.store is not None:
                return 'already unlocked'
            try:
                self.store = db.SecretStore.unlock(passphrase)
            except db.Locked:
                return 'incorrect global password'
            self.ready.set()
            return None


def peer_uid(conn):
    """The kernel's word for who is on the other end; a client cannot lie."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                          struct.calcsize('3i'))
    _pid, uid, _gid = struct.unpack('3i', raw)
    return uid


def _readline(conn, into):
    """One line into a bytearray the caller can wipe, a byte at a time: a
    passphrase must never land in an immutable bytes object we cannot scrub."""
    one = bytearray(1)
    while len(into) < MAX_LINE:
        if not conn.recv_into(one, 1) or one[0] == 0x0A:
            break
        into += one
    return into


def _serve_one(conn, gate, allow_uids):
    uid = peer_uid(conn)
    if uid not in allow_uids:
        conn.sendall(b'error: only root may use this socket\n')
        db.audit(f'uid {uid}', 'unlock-denied')
        logger.warning('unlock refused for uid %s', uid)
        return
    command = bytes(_readline(conn, bytearray())).decode('utf-8', 'replace').strip()
    if command == 'status':
        conn.sendall(b'unlocked\n' if gate.store is not None else b'locked\n')
        return
    if command != 'unlock':
        conn.sendall(b'error: expected "unlock" or "status"\n')
        return
    passphrase = bytearray()
    try:
        _readline(conn, passphrase)
        problem = gate.unlock(passphrase)
    finally:
        db.wipe(passphrase)
    if problem:
        db.audit(f'uid {uid}', 'unlock-failed')
        conn.sendall(f'error: {problem}\n'.encode())
        return
    db.audit(f'uid {uid}', 'unlock')
    logger.info('unlocked by uid %s', uid)
    sd_notify('STATUS=unlocked')
    conn.sendall(b'ok\n')


def serve(gate, path=None, allow_uids=ROOT_ONLY):
    """Listen in a background thread. allow_uids is widened only by the tests;
    production takes the default, which is root and nothing else."""
    path = Path(path or SOCKET)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    path.chmod(0o600)             # belt to the peer-credential braces
    srv.listen(4)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with contextlib.suppress(Exception), conn:
                _serve_one(conn, gate, allow_uids)

    threading.Thread(target=loop, daemon=True, name='unlock').start()


# --- client ---------------------------------------------------------------

def ask(command, passphrase=None, path=None):
    """Drive the socket from the CLI. Returns the daemon's one-line reply.

    Takes ownership of `passphrase` and wipes it, like SecretStore does with a
    key: one place scrubs it, so no caller can forget to."""
    path = str(path or SOCKET)
    payload = bytearray(command.encode() + b'\n')
    if passphrase is not None:
        payload += passphrase
        payload += b'\n'
        db.wipe(passphrase)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(60)
            sock.connect(path)
            sock.sendall(payload)
            return sock.recv(MAX_LINE).decode('utf-8', 'replace').strip()
    finally:
        db.wipe(payload)
