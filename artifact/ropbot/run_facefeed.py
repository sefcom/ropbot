import os
import time
import glob
import json

from multiprocessing import Process, cpu_count

import angr
import angrop

from utils import save_tmp_result, do_run, verify_facefeed

import logging
logging.getLogger('cle').setLevel("ERROR")
logging.getLogger('angrop').setLevel("ERROR")
logging.getLogger('angr').setLevel("ERROR")

CACHE_DIR = "/experiment/gadget_caches/"

def run(path):
    assert os.path.exists(path)
    entry = {
                "path": path,
                "size": os.path.getsize(path),
                "find_gadgets": None,
                "find_gadgets_time": None,
                "gadget_cnt": None,
                "builder_optimize": None,
                "builder_optimize_time": None,
                "chain_build": None,
                "chain_build_time": None,
                "chain_verify": None,
                "chain_verify_time": None,
                "chain_bytes": None,
                "chain_len": None,
            }
    name = os.path.basename(path)

    start = time.time()
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    if proj.arch.name == 'AMD64':
        rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    else:
        rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1, only_check_near_rets=False)
    try:
        cache = os.path.join(CACHE_DIR, name)
        if not os.path.exists(cache):
            rop.find_gadgets(processes=cpu_count(), show_progress=False, optimize=False, timeout=25*60)
            rop.save_gadgets(cache)
        else:
            rop.load_gadgets(cache, optimize=False)
        entry["find_gadgets"] = True
        entry["find_gadgets_time"] = time.time() - start
        entry["gadget_cnt"] = len(rop._all_gadgets)
        save_tmp_result(entry)
    except Exception:
        import traceback; traceback.print_exc()
        entry["find_gadgets"] = False
        entry["find_gadgets_time"] = time.time() - start
        save_tmp_result(entry)
        return

    start = time.time()
    try:
        rop.chain_builder.optimize(processes=cpu_count())
        entry["builder_optimize"] = True
        entry["builder_optimize_time"] = time.time() - start
        save_tmp_result(entry)
    except Exception:
        import traceback; traceback.print_exc()
        entry["builder_optimize"] = False
        entry["builder_optimize_time"] = time.time() - start
        save_tmp_result(entry)
        return

    start = time.time()
    try:
        chain = rop.func_call(0xfacefeed, [0xdeadbeef, 0x40, 0x7b], needs_return=False)
        entry["chain_build"] = True
        entry["chain_build_time"] = time.time() - start
        payload = chain.payload_str()
        entry["chain_bytes"] = payload.hex()
        save_tmp_result(entry)
    except angrop.errors.RopException:
        entry["chain_build"] = False
        entry["chain_build_time"] = time.time() - start
        save_tmp_result(entry)
        return
    except Exception:
        import traceback; traceback.print_exc()
        entry["chain_build"] = False
        entry["chain_build_time"] = time.time() - start
        save_tmp_result(entry)
        return

    chain.pp()

def verify(entry):
    start = time.time()
    path = entry["path"]
    payload = bytes.fromhex(entry["chain_bytes"]) if "chain_bytes" in entry  and entry["chain_bytes"] is not None else None
    if payload is None:
        return
    try:
        verify_facefeed(path, payload)
        entry["chain_verify"] = True
        entry["chain_verify_time"] = time.time() - start
        save_tmp_result(entry)
    except Exception:
        entry["chain_verify"] = False
        entry["chain_verify_time"] = time.time() - start
        save_tmp_result(entry)

if __name__ == '__main__':
    do_run(run, verify)
