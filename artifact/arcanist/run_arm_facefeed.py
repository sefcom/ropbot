import os
import re
import glob
import time
import json
import datetime
import subprocess

from multiprocessing import Process, cpu_count

from pwnlib.tubes.process import process

from utils import save_tmp_result, do_run

GADGET_PATH = "/tmp/gadgets"
SAMPLE_SIZE = 600
MAX_GADGET_NUM = 8

def run(path):
    assert os.path.exists(path)
    entry = { 
                "path": path,
                "size": os.path.getsize(path),
                "find_gadgets": None,
                "find_gadgets_time": None,
                "gadget_cnt": None,
                "chain_build": None,
                "chain_build_time": None,
                "chain_output": None,
                "runner_failed": None,
                "arcanist_failed": None,
            }
    save_tmp_result(entry)

    try:
        start = time.time()
        proc = process(["/binaryninja/bnpython3", "/arcanist/arcanist_tools/extract.py", path, GADGET_PATH])
        proc.recvuntil(b"Done translating")
        line = proc.recvline()
        res = re.search(b'(\\d+) gadgets', line)
        assert res is not None
        gadget_num = int(res.group(1))
        entry['find_gadgets'] = True
        entry['find_gadgets_time'] = time.time() - start
        entry['gadget_cnt'] = gadget_num
        save_tmp_result(entry)
        proc.wait()
        proc.close()

        start = time.time()
        proc = process(["python", "/arcanist/arcanist_tools/benchmark.py", "--strategy", "incremental", "--timeout", "3600",
                        "--jobs", str(cpu_count()), path, GADGET_PATH, str(MAX_GADGET_NUM), str(SAMPLE_SIZE), "ropbot-arm-facefeed"])
        try:
            while not proc.stdout.closed:
                line = proc.recvregex(b'^.*(\r|\n)')
                if b"Unable to find chain..." in line:
                    entry['chain_build'] = False
                    entry['chain_build_time'] = time.time() - start
                    save_tmp_result(entry)
                    break
                if b"Successfully found chain" in line:
                    output = proc.recvall()
                    entry['chain_build'] = True
                    entry['chain_build_time'] = time.time() - start
                    entry['chain_output'] = output.hex()
                    save_tmp_result(entry)
                    break
                if b"Traceback (most recent call last)" in line:
                    print('Traceback (most recent call last)')
                    print(proc.recv().decode())
                    entry["arcanist_failed"] = True
                    entry['chain_build_time'] = time.time() - start
                    save_tmp_result(entry)
                    break
        except EOFError:
            pass

    except Exception as e:
        entry["runner_failed"] = True
        save_tmp_result(entry)
        print('='*0x10)
        import traceback;traceback.print_exc()
        print('='*0x10)
        proc.close()

def noop(entry):
    pass

if __name__ == "__main__":
    do_run(run, noop)
