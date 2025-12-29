import os
import glob
import time

from multiprocessing import cpu_count
from pwnlib.elf import ELF

from Exrop import Exrop

from utils import save_tmp_result, do_run, verify_dup

import angr

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
            }
    save_tmp_result(entry)

    start = time.time()
    try:
        rop = Exrop(path)
        rop.find_gadgets(cache=True, num_process=cpu_count())
        entry["find_gadgets"] = True
        entry["find_gadgets_time"] = time.time() - start
        entry["gadget_cnt"] = len(rop.chain_builder.gadgets)
        save_tmp_result(entry)
    except Exception:
        entry["find_gadgets"] = False
        entry["find_gadgets_time"] = time.time() - start
        save_tmp_result(entry)
        return

    start = time.time()
    try:
        e = ELF(path)
        chain1 = rop.func_call(e.plt['dup2'], (3, 0))
        chain2 = rop.func_call(e.plt['dup2'], (3, 1))
        chain3 = rop.syscall(0x3b, ('/bin/sh\x00', 0, 0), e.bss())
        chain = chain1 + chain2 + chain3
        entry["chain_build"] = True
        entry["chain_build_time"] = time.time() - start
        payload = chain.payload_str()
        entry["chain_bytes"] = payload.hex()
        save_tmp_result(entry)
    except Exception:
        entry["chain_build"] = False
        entry["chain_build_time"] = time.time() - start
        save_tmp_result(entry)
        return

    chain.dump()

def verify(entry):
    start = time.time()
    path = entry["path"]
    payload = bytes.fromhex(entry["chain_bytes"]) if "chain_bytes" in entry and entry["chain_bytes"] else None
    if payload is None:
        return
    try:
        verify_dup(path, payload)
        entry["chain_verify"] = True
        entry["chain_verify_time"] = time.time() - start
        save_tmp_result(entry)
    except Exception:
        entry["chain_verify"] = False
        entry["chain_verify_time"] = time.time() - start
        save_tmp_result(entry)

if __name__ == "__main__":
    # remove corrupted cache files
    for path in glob.glob("/experiment/*.exrop_cache"):
        if os.path.getsize(path) == 0:
            os.unlink(path)
    do_run(run, verify)
