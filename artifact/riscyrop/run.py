import os
import time
import shutil
import hashlib
import tempfile
import subprocess

from multiprocessing import cpu_count

import sqlite3
from utils import save_tmp_result, do_run, verify_riscyrop
from pwnlib.tubes.process import process

ARCH = None
FIND_GADGET_TIMEOUT = "25m"
CHAIN_TIMEOUT = 30*60

def find_gadgets(path):
    with tempfile.TemporaryDirectory(prefix='riscyrop') as folder:
        dst = os.path.join(folder, os.path.basename(path))
        shutil.copy(path, dst)
        cpu_num = cpu_count()
        out = dst+".out"
        err = dst+".err"
        cmd = f'python ./find_gadgets.py --{ARCH} -s "' + path + '" 0x100 {} "$@" > ' + f'"{out}"' + ' 2>"' + err + '"'
        prefix = f'seq 0 10000 | parallel --halt soon,fail=500 -j{cpu_num} --timeout {FIND_GADGET_TIMEOUT}'
        cmd = f'{prefix} {cmd}'
        os.system(cmd)
    return

def run(path):
    assert os.path.exists(path)
    entry = { 
                "path": path,
                "size": os.path.getsize(path),
                "find_gadgets": None,
                "gadget_cnt": None,
                "find_gadgets_time": None,
                "chain_build": None,
                "chain_build_time": None,
                "chain_verify": None,
                "chain_verify_time": None,
                "chain_bytes": None,
                "chain_len": None,
                "runner_failed" : None,
            }
    save_tmp_result(entry)

    start = time.time()
    try:
        find_gadgets(path)
        entry["find_gadgets"] = True
        entry["find_gadgets_time"] = time.time() - start

        db = sqlite3.connect("./rop_analysis.db")
        with open(path, 'rb') as f:
            bin_hash = hashlib.sha256(f.read(), usedforsecurity=False).hexdigest()
        (binary,), = db.execute("SELECT bin_id FROM binaries WHERE sha256 = ?", [bin_hash]).fetchall()
        gadgets = list(db.execute(f"select address from gadgets where `binary`={binary}"))
        entry["gadget_cnt"] = len(gadgets)
        save_tmp_result(entry)
        db.close()
    except Exception:
        entry["runner_failed"] = True
        save_tmp_result(entry)
        return

    payload = None
    chain = None
    start = time.time()
    try:
        proc = process(['python', './chaining.py', path, '3'])
        while not proc.stdout.closed:
            line = proc.recvregex(b'^.*(\r|\n)')
            if b"Instruction Count:" in line:
                payload = proc.recvline().split()[0].decode()
                payload = bytes.fromhex(payload)
                entry['chain_build'] = True
                entry['chain_build_time'] = time.time() - start
                entry["chain_bytes"] = payload.hex()
                save_tmp_result(entry)
                break
    except EOFError:
        pass
    except Exception:
        entry["runner_failed"] = True
        save_tmp_result(entry)
        return

    if payload is None:
        entry['chain_build'] = False
        entry['chain_build_time'] = time.time() - start
        save_tmp_result(entry)
        return

def verify(entry):
    start = time.time()
    path = entry["path"]
    payload = bytes.fromhex(entry["chain_bytes"]) if "chain_bytes" in entry else None
    if payload is None:
        return
    try:
        verify_riscyrop(path, payload)
        entry["chain_verify"] = True
        entry["chain_verify_time"] = time.time() - start
        save_tmp_result(entry)
    except Exception:
        entry["chain_verify"] = False
        entry["chain_verify_time"] = time.time() - start
        save_tmp_result(entry)

if __name__ == '__main__':
    import sys
    assert sys.argv[1] in ('riscv', 'aarch64')
    ARCH = sys.argv[1]
    #run("/dataset/libnvidia-gl-550-server-libnvidia-egl-gbm.so.1.1.1")
    do_run(run, verify)
