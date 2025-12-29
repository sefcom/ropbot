import os
import time
import glob
import json
import tempfile
import subprocess
import signal
import ctypes
import string
import random

from jinja2 import Template
from multiprocessing import cpu_count

import angr

from utils import save_tmp_result, do_run, verify_mmap

FIND_GADGET_TIMEOUT = 30*60
CHAIN_BUILD_TIMEOUT = 30*60
TARGET_CONFIG_TEMPLATE_PATH = '/experiment/templates/mmap_config.json.j2'
SGC_CONFIG_TEMPLATE_PATH = '/experiment/templates/synthesizer_config.json.j2'
TARGET_DIR = "/experiment/targets/"
RESULT_DIR = "/experiment/results/"
SGC_CONFIG_PATH = "synthesizer_config_default.json"
SGC_TMP_GADGET_DIR = "/tmp/SGC-gadget"

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
def set_pdeathsig(sig):
    def callable():
        return libc.prctl(1, sig)
    return callable

with open(TARGET_CONFIG_TEMPLATE_PATH) as f:
    target_config_template = Template(f.read())
with open(SGC_CONFIG_TEMPLATE_PATH) as f:
    sgc_config_template = Template(f.read())

def rand_str(N):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=N))

def prep_target(path):
    name = os.path.basename(path)

    # create a target folder
    target_path = os.path.join(TARGET_DIR, name)
    os.makedirs(target_path, exist_ok=True)
    bin_path = os.path.join(target_path, "library_target")
    os.system(f"cp '{path}' '{bin_path}'")
    proj = angr.Project(bin_path, load_options={'main_opts':{'base_addr': 0}})

    # find a ret_addr
    ret_addr = None
    for seg in proj.loader.main_object.segments:
        if not seg.is_executable:
            continue
        start = seg.min_addr
        end = seg.min_addr + seg.memsize
        for addr in range(start, end, 0x400):
            read_size = min(0x400, end-addr)
            data = proj.loader.memory.load(addr, read_size)
            if b'\xc3' in data:
                idx = data.index(b'\xc3') # find a ret
                ret_addr = addr + idx
                break
        if ret_addr is not None:
            break
    assert ret_addr is not None

    # find all the readable/writable ranges
    read_segs = []
    write_segs = []
    for seg in proj.loader.main_object.segments:
        if seg.is_readable:
            read_segs.append(seg)
        if seg.is_writable:
            write_segs.append(seg)
    read_seg_str = ', '.join([str([hex(seg.min_addr), hex(seg.min_addr+seg.memsize)]) for seg in read_segs])
    read_seg_str = read_seg_str.replace("'", '"')
    write_seg_str = ', '.join([str([hex(seg.min_addr), hex(seg.min_addr+seg.memsize)]) for seg in write_segs] + [str(["0x7ffffffde000", "0x7ffffffff000"])])
    write_seg_str = write_seg_str.replace("'", '"')

    # write the config.json
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    mmap_addr = proj.loader.main_object.plt['mmap']
    try:
        config_data = target_config_template.render(path=bin_path, ret_addr=hex(ret_addr), read_seg_str=read_seg_str, write_seg_str=write_seg_str, mmap_addr=hex(mmap_addr))
    except Exception:
        pass
    print(config_data)
    with open(os.path.join(target_path, "config.json"), "w") as f:
        f.write(config_data)
    return target_path

def find_verified_results(iter_path):
    bins = []
    results = glob.glob(os.path.join(iter_path, "*", "*", "result.json"))
    for result in results:
        with open(result) as f:
            data = json.loads(f.read())
        if 'verification' in data and data['verification'] is True:
            bin_path = os.path.join(os.path.dirname(result), 'stack.bin')
            if os.path.exists(bin_path):
                bins.append(bin_path)
    return bins

def run(path):
    assert os.path.exists(path)
    name = os.path.basename(path)
    entry = {
                "path": path,
                "size": os.path.getsize(path),
                "prep_target": None,
                "find_gadgets": None,
                "find_gadgets_time": None,
                "gadget_cnt": None,
                "chain_build": None,
                "chain_build_time": None,
                "chain_verify": None,
            }
    save_tmp_result(entry)

    try:
        target_path = prep_target(path)
        entry['prep_target'] = True
        save_tmp_result(entry)
    except Exception:
        entry['prep_target'] = False
        save_tmp_result(entry)
        return

    # write one SGC config for gadget finding, it will be cached into the target folder
    # so we can freely destroy the tmpdir
    start = time.time()
    try:
        with open(SGC_CONFIG_PATH, 'w') as f:
            data = sgc_config_template.render(iteration=5)
            f.write(data)
        args = ["/opt/venv/bin/python", "/gadget_synthesis/extractor.py", "-o", SGC_TMP_GADGET_DIR+rand_str(10), "-j", str(cpu_count()), target_path]
        proc = subprocess.Popen(args, preexec_fn = set_pdeathsig(signal.SIGKILL))
        try:
            proc.wait(timeout=FIND_GADGET_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
        entry['find_gadgets'] = True
        entry['find_gadgets_time'] = time.time() - start
        with open(os.path.join(target_path, ".cache", 'gadgets.json')) as f:
            gadgets = json.load(f)
            entry['gadget_cnt'] = len(gadgets)
        save_tmp_result(entry)
    except Exception:
        entry['find_gadgets'] = False
        entry['find_gadgets_time'] = time.time() - start
        save_tmp_result(entry)
        return

    # run SGC for iteration 1-5 until if finds a chain
    start = time.time()
    bins = None
    for i in range(1, 6):
        result_path = os.path.join(RESULT_DIR, name)
        os.makedirs(result_path, exist_ok=True)
        iter_path = os.path.join(result_path, f"iter{i}")
        # write a new SGC config for the iteration config
        with open(SGC_CONFIG_PATH, 'w') as f:
            data = sgc_config_template.render(iteration=i)
            f.write(data)
        args = ["/opt/venv/bin/python", "/gadget_synthesis/synthesizer.py", "-o", iter_path, "-j", str(cpu_count()), target_path]
        proc = subprocess.Popen(args, preexec_fn = set_pdeathsig(signal.SIGKILL))
        try:
            proc.wait(timeout=CHAIN_BUILD_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
        res = find_verified_results(iter_path)
        if res:
            bins = res
            break
    else:
        entry['chain_build'] = False
        entry['chain_build_time'] = time.time() - start
        save_tmp_result(entry)
        return

    entry['chain_build'] = True
    entry['chain_build_time'] = time.time() - start
    assert bins is not None

    payload_list = []
    for bin_path in bins:
        with open(bin_path, 'rb') as f:
            payload = f.read()
            payload_list.append(payload.hex())

    entry['payload_list'] = payload_list
    save_tmp_result(entry)

def verify(entry):
    payload_list = entry['payload_list'] if 'payload_list' in entry and entry['payload_list'] else []
    path = entry["path"]

    # now verify the chains
    result1 = []
    result2 = []
    for payload_str in payload_list:
        payload = bytes.fromhex(payload_str)

        print('verifying1...', payload)
        start = time.time()
        try:
            verify_mmap(path, payload, known_payload_addr=False)
            result1.append((True, time.time()-start, payload.hex()))
        except Exception:
            result1.append((False, time.time()-start, payload.hex()))

        print('verifying2...', payload)
        start = time.time()
        try:
            verify_mmap(path, payload, known_payload_addr=True)
            result2.append((True, time.time()-start, payload.hex()))
        except Exception:
            result2.append((False, time.time()-start, payload.hex()))

    entry['chain_verify_unknown_payload_addr'] = result1
    entry['chain_verify_known_payload_addr'] = result2
    if 'payload_list' in entry:
        del entry['payload_list']
    save_tmp_result(entry)

if __name__ == "__main__":
    os.makedirs(TARGET_DIR, exist_ok=True)
    do_run(run, verify)
