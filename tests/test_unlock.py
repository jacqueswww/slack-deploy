#!/usr/bin/env python3
"""The root-only unlock socket that replaces a console password prompt."""
import os
import socket
import sys

import harness
from harness import BAD, GOOD

import db
import unlock

CTX = {}


def a_fresh_daemon_is_locked():
    harness.new_store().close()
    gate = unlock.Gate()
    CTX['gate'] = gate
    CTX['path'] = db.DATA.parent / 'run' / 'unlock.sock'
    # the tests are not root, so they allow their own uid; production takes the
    # default, which the next check pins to root and nothing else
    CTX['srv'] = unlock.serve(gate, CTX['path'], allow_uids=(os.getuid(),))
    assert gate.store is None and not gate.ready.is_set()
    assert unlock.ask('status', path=CTX['path']) == 'locked'
    assert CTX['path'].stat().st_mode & 0o777 == 0o600, oct(CTX['path'].stat().st_mode)
    assert CTX['path'].parent.stat().st_mode & 0o777 == 0o700


def only_root_may_drive_it_in_production():
    """The file mode already limits the socket to the daemon's own uid, but a
    playbook that has gone bad runs as that uid, so the peer is checked too."""
    assert unlock.ROOT_ONLY == (0,), unlock.ROOT_ONLY
    import inspect
    assert inspect.signature(unlock.serve).parameters['allow_uids'].default == (0,), \
        'the shipped default must be root only'
    strict = db.DATA.parent / 'run' / 'strict.sock'
    unlock.serve(unlock.Gate(), strict)          # default allow_uids
    reply = unlock.ask('status', path=strict)
    assert reply.startswith('error:') and 'root' in reply, reply
    assert unlock.ask('unlock', bytearray(GOOD.encode()), path=strict).startswith('error:')


def a_wrong_password_leaves_it_locked():
    reply = unlock.ask('unlock', bytearray(BAD.encode()), path=CTX['path'])
    assert reply == 'error: incorrect global password', reply
    assert CTX['gate'].store is None and not CTX['gate'].ready.is_set()
    assert unlock.ask('status', path=CTX['path']) == 'locked'


def rubbish_is_refused_without_touching_the_gate():
    for command in ('', 'quit', 'UNLOCK', 'status extra'):
        reply = unlock.ask(command, path=CTX['path'])
        assert reply.startswith('error:'), (command, reply)
    assert CTX['gate'].store is None


def the_right_password_unlocks_the_daemon():
    gate = CTX['gate']
    assert unlock.ask('unlock', bytearray(GOOD.encode()), path=CTX['path']) == 'ok'
    assert gate.ready.wait(5), 'the daemon must be released'
    assert gate.store is not None
    assert gate.store.get(db.GLOBAL_SCOPE, 0, 'nothing') is None, 'the store must work'
    assert unlock.ask('status', path=CTX['path']) == 'unlocked'
    assert unlock.ask('unlock', bytearray(GOOD.encode()), path=CTX['path']) == \
        'error: already unlocked', 'a second unlock must not replace the key'


def every_attempt_is_audited():
    with db.deploy_conn() as conn:
        actions = [r['action'] for r in conn.execute(
            'SELECT action FROM audit ORDER BY id')]
    for wanted in ('unlock', 'unlock-failed', 'unlock-denied'):
        assert wanted in actions, (wanted, actions)


def the_passphrase_is_wiped_after_it_is_sent():
    """The client's copy is a bytearray precisely so it can be scrubbed."""
    typed = bytearray(GOOD.encode())
    unlock.ask('status', typed, path=CTX['path'])
    assert not any(typed), 'ask() must wipe what it sent'


def the_cli_talks_to_the_module_not_a_shadow():
    """manage.py had its own unlock() helper, which shadowed this module and made
    every `hoisty unlock` an AttributeError."""
    import manage
    assert manage.unlock is unlock, 'the module must not be shadowed by a function'
    assert callable(manage.unlock_store), 'the passphrase helper keeps its own name'


def a_missing_daemon_is_an_error_not_a_traceback():
    try:
        unlock.ask('status', path=db.DATA.parent / 'run' / 'nope.sock')
        raise AssertionError('connecting to nothing must raise')
    except OSError:
        pass


def sd_notify_is_a_no_op_off_systemd():
    os.environ.pop('NOTIFY_SOCKET', None)
    unlock.sd_notify('STATUS=x')                      # must not raise
    path = str(db.DATA.parent / 'run' / 'notify.sock')
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as srv:
        srv.bind(path)
        os.environ['NOTIFY_SOCKET'] = path
        try:
            unlock.sd_notify('READY=1\nSTATUS=locked')
            srv.settimeout(5)
            assert srv.recv(100) == b'READY=1\nSTATUS=locked'
        finally:
            os.environ.pop('NOTIFY_SOCKET', None)


if __name__ == '__main__':
    sys.exit(harness.run(
        a_fresh_daemon_is_locked, only_root_may_drive_it_in_production,
        a_wrong_password_leaves_it_locked, rubbish_is_refused_without_touching_the_gate,
        the_right_password_unlocks_the_daemon, every_attempt_is_audited,
        the_passphrase_is_wiped_after_it_is_sent, the_cli_talks_to_the_module_not_a_shadow,
        a_missing_daemon_is_an_error_not_a_traceback, sd_notify_is_a_no_op_off_systemd))
