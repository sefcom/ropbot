import os
import re
import glob
import time
import json
import datetime
import subprocess

from multiprocessing import Process, cpu_count

from jinja2 import Template
from pwnlib.tubes.process import process

from utils import save_tmp_result, do_run

CONFIG_TEMPLATE_PATH = '/experiment/templates/config.toml.j2'
SPEC_PATH = '/experiment/facefeed.o'
CONFIG_PATH = "/experiment/config.toml"

with open(CONFIG_TEMPLATE_PATH) as f:
    config_template = Template(f.read())

def escape_ansi(line):
    ansi_escape = re.compile(b'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub(b'', line)

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
            }
    save_tmp_result(entry)

    # create the config
    with open(CONFIG_PATH, 'w') as f:
        data = config_template.render(spec_path=SPEC_PATH, bin_path=path, cpu_count=cpu_count())
        f.write(data+'\n')

    init = time.time()
    init_utc = datetime.datetime.now(datetime.UTC)

    try:
        start = time.time()
        proc = process(["/usr/bin/crackers", "synth", CONFIG_PATH])
        proc.recvline()
        line = escape_ansi(proc.recvline())
        res = re.search(b'Found (\\d+) gadgets', line)
        assert res is not None
        gadget_num = int(res.group(1))
        ts1 = datetime.datetime.fromisoformat(line.decode().split()[0])
        print("gadget count:", gadget_num)
        entry['find_gadgets'] = True
        entry['find_gadgets_time'] = (ts1 - init_utc).total_seconds()
        entry['gadget_cnt'] = gadget_num
        save_tmp_result(entry)

        try:
            while not proc.stdout.closed:
                line = proc.recvregex(b'^.*(\r|\n)')
                if b"Synthesis unsuccessful" in line or b'The specification computation had no operations' in line:
                    line = escape_ansi(line)
                    ts2 = datetime.datetime.fromisoformat(line.decode().split()[0])
                    entry['chain_build'] = False
                    entry['chain_build_time'] = (ts2-ts1).total_seconds()
                    save_tmp_result(entry)
                    break
                if b"Synthesis successful" in line:
                    line = escape_ansi(line)
                    ts2 = datetime.datetime.fromisoformat(line.decode().split()[0])
                    output = proc.recvall()
                    output = escape_ansi(output)
                    entry['chain_build'] = True
                    entry['chain_build_time'] = (ts2-ts1).total_seconds()
                    entry['chain_output'] = output.hex()
                    save_tmp_result(entry)
                    break
        except EOFError:
            pass

        proc.close()

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
