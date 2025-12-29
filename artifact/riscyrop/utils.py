import os
import time
import glob
import json

from multiprocessing import Process

import angr, angrop

TIMEOUT = 30*60
DATASET_DIR = "/dataset"
RESULT_PATH = "/experiment/output.jsonl"
TMP_RESULT = '/tmp/out.json'

def cleanup_tmp_result():
    if os.path.exists(TMP_RESULT):
        os.unlink(TMP_RESULT)

def save_tmp_result(entry):
    with open(TMP_RESULT, 'w') as f:
        f.write(json.dumps(entry))

def get_entry(path):
    if os.path.exists(TMP_RESULT):
        with open(TMP_RESULT, 'r') as f:
            entry = json.loads(f.read())
    else:
        entry = {"path": path}
    return entry

def save_result(path, is_timeout):
    entry = get_entry(path)
    if is_timeout:
        entry['timeout'] = True
    print(entry)
    with open(RESULT_PATH, "a") as f:
        f.write(json.dumps(entry) + '\n')

def concrete_exec_til_addr(state, target_addr):
    simgr = state.project.factory.simgr(state)
    while simgr.one_active.addr != target_addr:
        simgr.step()
        assert len(simgr.active) == 1, simgr.active
    return simgr.one_active

def verify_facefeed(path, payload, known_payload_addr=False):
    assert isinstance(payload, bytes)
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP()
    arch_bytes = proj.arch.bytes
    state = angrop.rop_utils.make_symbolic_state(proj, rop.arch.reg_set, stack_gsize=0)
    if known_payload_addr:
        state.regs.sp = 0x00007fffffffe498 # for SGC speficically
    state.memory.store(state.regs.sp, payload)
    state.ip = state.stack_pop()

    state = concrete_exec_til_addr(state, 0xfacefeed)
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert state.ip.concrete_value == 0xfacefeed
    assert state.registers.load(cc.ARG_REGS[0]).concrete_value == 0xdeadbeef
    assert state.registers.load(cc.ARG_REGS[1]).concrete_value == 0x40
    assert state.registers.load(cc.ARG_REGS[2]).concrete_value == 0x7b

def verify_mmap(path, payload, known_payload_addr=False):
    assert isinstance(payload, bytes)
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP()
    arch_bytes = proj.arch.bytes
    state = angrop.rop_utils.make_symbolic_state(proj, rop.arch.reg_set, stack_gsize=0)
    if known_payload_addr:
        state.regs.sp = 0x00007fffffffe498 # for SGC speficically
    state.memory.store(state.regs.sp, payload)
    state.ip = state.stack_pop()

    assert 'mmap' in proj.loader.main_object.plt
    mmap_addr = proj.loader.main_object.plt['mmap']
    state = concrete_exec_til_addr(state, mmap_addr)
    assert state.regs.rdi.concrete_value == 0x41414000
    assert state.regs.rsi.concrete_value == 0x1000
    assert state.regs.rdx.concrete_value == 7
    assert state.regs.rcx.concrete_value == 50
    assert state.regs.r8.concrete_value in (-1, 0xffffffffffffffff)
    assert state.regs.r9.concrete_value == 0

def verify_execve(path, payload, known_payload_addr=False):
    assert isinstance(payload, bytes)
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP()
    arch_bytes = proj.arch.bytes
    state = angrop.rop_utils.make_symbolic_state(proj, rop.arch.reg_set, stack_gsize=0)
    if known_payload_addr:
        state.regs.sp = 0x00007fffffffe498 # for SGC speficically
    state.memory.store(state.regs.sp, payload)
    state.ip = state.stack_pop()

    # step to the system call
    simgr = proj.factory.simgr(state)
    while simgr.active:
        assert len(simgr.active) == 1
        state = simgr.active[0]
        obj = proj.loader.find_object_containing(state.ip.concrete_value)
        if obj and obj.binary == 'cle##kernel':
            break
        simgr.step()

    # verify the syscall arguments
    state = simgr.active[0]
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert cc.syscall_num(state).concrete_value == 0x3b
    ptr = state.registers.load(cc.ARG_REGS[0])
    assert state.solver.is_true(state.memory.load(ptr, 8) == b'/bin/sh\0')
    assert state.registers.load(cc.ARG_REGS[1]).concrete_value == 0
    assert state.registers.load(cc.ARG_REGS[2]).concrete_value == 0

def verify_riscyrop(path, payload, known_payload_addr=False):
    assert isinstance(payload, bytes)
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP()
    arch_bytes = proj.arch.bytes
    state = angrop.rop_utils.make_symbolic_state(proj, rop.arch.reg_set, stack_gsize=0)
    if known_payload_addr:
        state.regs.sp = 0x00007fffffffe498 # for SGC speficically
    state.memory.store(state.regs.sp, payload)
    state.ip = state.stack_pop()

    state = concrete_exec_til_addr(state, 0xdeadbeef)
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert state.ip.concrete_value == 0xdeadbeef
    assert state.registers.load(cc.ARG_REGS[0]).concrete_value == 0x40404040
    assert state.registers.load(cc.ARG_REGS[1]).concrete_value == 0x41414141
    assert state.registers.load(cc.ARG_REGS[2]).concrete_value == 0x42424242

dup_cnt = 0
class NopDup2(angr.SimProcedure):
   def run(self, oldfd, newfd):
       global dup_cnt
       dup_cnt += 1
       return newfd

def verify_dup(path, payload, known_payload_addr=False):
    global dup_cnt

    assert isinstance(payload, bytes)
    proj = angr.Project(path, load_options={'main_opts':{'base_addr': 0}})
    dup2_addr = proj.loader.main_object.plt['dup2']
    proj.hook(dup2_addr, NopDup2())
    rop = proj.analyses.ROP()
    arch_bytes = proj.arch.bytes
    state = angrop.rop_utils.make_symbolic_state(proj, rop.arch.reg_set, stack_gsize=0)
    if known_payload_addr:
        state.regs.sp = 0x00007fffffffe498 # for SGC speficically
    state.memory.store(state.regs.sp, payload)
    state.ip = state.stack_pop()

    # step to the system call
    simgr = proj.factory.simgr(state)
    while simgr.active:
        assert len(simgr.active) == 1
        state = simgr.active[0]
        obj = proj.loader.find_object_containing(state.ip.concrete_value)
        if obj and obj.binary == 'cle##kernel':
            break
        simgr.step()

    # verify the syscall arguments
    state = simgr.active[0]
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert dup_cnt == 2
    assert cc.syscall_num(state).concrete_value == 0x3b
    ptr = state.registers.load(cc.ARG_REGS[0])
    assert state.solver.is_true(state.memory.load(ptr, 8) == b'/bin/sh\0')
    assert state.registers.load(cc.ARG_REGS[1]).concrete_value == 0
    assert state.registers.load(cc.ARG_REGS[2]).concrete_value == 0
    dup_cnt = 0

def do_run(run, cb):
    fpaths = glob.glob(os.path.join(DATASET_DIR, "*"))
    fpaths = sorted(fpaths)
    for path in fpaths:
        cleanup_tmp_result()

        # run each test in a subprocess
        print(path)
        proc = Process(target=run, args=(path,))
        proc.start()
        proc.join(TIMEOUT)
        is_timeout = True if proc.exitcode is None else False
        proc.terminate()
        proc.kill()

        entry = get_entry(path)
        cb(entry)
        save_result(path, is_timeout)

    print('='*0x10)
    print("Experiment finished!!!!")
    while True:
        time.sleep(1000000)
