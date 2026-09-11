"""Shared setup for the test files. Importing this must happen before `db`.

Each test file runs as its own process, so each gets its own data directory and
the files stay independent of one another.
"""
import atexit
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = Path(tempfile.mkdtemp(prefix='hoisty-tests-'))
os.environ['HOISTY_DATA'] = str(WORK / 'data')
os.environ['HOISTY_RUNTIME'] = str(WORK / 'run')
sys.path[:0] = [str(ROOT / 'src'), str(ROOT)]

GOOD = 'a shared passphrase long enough'
BAD = 'not the right passphrase!!'

atexit.register(lambda: shutil.rmtree(WORK, ignore_errors=True))


def new_store(passphrase=GOOD):
    import db
    return db.init(passphrase)


def run(*checks):
    """Run each check in order, print one line each, exit non-zero on failure."""
    name = Path(sys.argv[0]).stem
    for check in checks:
        try:
            check()
        except Exception:
            print(f'{name}: {check.__name__} FAILED')
            traceback.print_exc()
            return 1
        print(f'  ok  {check.__name__}')
    print(f'{name}: {len(checks)} checks passed')
    return 0
