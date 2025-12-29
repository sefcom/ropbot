import functools
import hashlib
import sqlite3
import time
from collections import defaultdict
from concurrent.futures.process import ProcessPoolExecutor
from pathlib import Path
from typing import Iterable, Sequence

import struct

import regex as re

from find_gadgets import GadgetFinder
from misc import NameAnnotation, REGS

pass
import archinfo
import claripy
import angr
from angr.calling_conventions import register_default_cc, register_syscall_cc
from angr.engines import UberEnginePcode
from angr_platforms.risc_v import SimCCRISCV, SimRISCVSyscall

register_default_cc('RISCV:LE:64:default', SimCCRISCV)
register_syscall_cc('RISCV:LE:64:default', "default", SimRISCVSyscall)

_find_gadget_iter_cache = {}

def p64(data):
    return struct.pack('<Q', data)

def find_gadget_iter_cache(binary, regs: set[str], stack_ret=False):
    global _find_gadget_iter_cache
    key = (binary, stack_ret) + tuple(sorted(regs))
    val = _find_gadget_iter_cache.get(key, None)
    if val is None:
        _find_gadget_iter_cache[key] = val = list(find_gadget_iter(binary, regs, stack_ret))
    return val


def find_gadget_iter(binary, regs: set[str], stack_ret=False):
    assert len(regs), "len(regs)==0"
    # reg_stack_search = "+".join(f"(instr(replace(reg_stack_read,'w','x'), '{reg}') IS TRUE)" for reg in regs)
    # reg_moved_search = "+".join(f"(instr(replace(reg_moved,'w','x'), '-> {reg}') IS TRUE)" for reg in regs)
    # reg_other_search = "+".join(f"(instr(replace(reg_other,'w','x'), '{reg},') IS TRUE)" for reg in regs) + "+" + "+".join(f"(instr(replace(reg_other,'w','x'), '{reg}=') IS TRUE)" for reg in regs)
    reg_stack_search = "+".join(rf"(reg_stack_read REGEXP '\b{reg.replace('x', '[xw]')}\b')" for reg in regs)
    reg_moved_search = "+".join(rf"(reg_moved REGEXP '-> {reg.replace('x', '[xw]')}\b')" for reg in regs)
    reg_other_search = "+".join(rf"(reg_other REGEXP '\b{reg.replace('x', '[xw]')}\b')" for reg in regs)
    last_instr_search = "+".join(rf"(last_instr REGEXP '\b{reg.replace('x', '[xw]')}\b')" for reg in regs)
    stack_search = "return_type LIKE 'Stack %'" if stack_ret else "1"

    print("ITER search", regs, stack_ret)

    query = (
        f"SELECT address, return_type, ra, pop_size, "
        f"  reg_stack_read, replace(reg_moved, 'w', 'x') as reg_moved2, reg_other, "
        f"  solver_constraints, "
        f"  instructions, last_instr, last_instr_addr, "
        f"  {reg_stack_search} + {reg_moved_search} as matches, "
        f"  {reg_stack_search} as matches_stack, "
        f"  {reg_moved_search} as matches_move "
        f"FROM gadgets "
        f"WHERE `binary` = ? AND pop_size >= 0 "
        f"  AND NOT instr(instructions, 'svc') AND instruction_count < 25 "
        f"  AND matches >= 1 AND {stack_search} AND {reg_other_search} = 0 AND {last_instr_search} = 0 "
        f"ORDER BY matches DESC, instr(return_type, 'Stack') IS TRUE DESC, {reg_stack_search} DESC, {reg_moved_search} DESC, instruction_count "
        # f"LIMIT 20 "
    )
    results = db.execute(query, [binary]).fetchall()
    if not results:
        print("ITER NO RESULTS")
        print(query.replace('?', str(binary)))
        return
    print("ITER results", len(results))
    first_matches = results[0][-3]
    for i, (address, return_type, ra, pop_size, reg_stack_read, reg_moved, reg_other, solver_constraints, instructions, last_instr, last_instr_addr, matches, matches_stack, matches_move) in enumerate(results):
        # print("ITER gadget", i, f"{address=:#x}, {return_type=}, {reg_stack_read=}, {reg_moved=}, {reg_other=}, {last_instr=}, {matches=}")
        if i > 20 and matches < first_matches // 2:
            break
        yield address
    print("ITER stopping at", i, address, matches, regs)


def find_gadget(binary, regs: set[str], stack_ret=False):
    return next(find_gadget_iter(binary, regs, stack_ret))


def parse_moved(moved_str: str) -> dict[str, str]:
    """:returns {dst: src, ...}"""
    return {x[1]: x[0] for m in moved_str.split(", ") if len(x := m.split(" -> ")) == 2}


checked_gadgets = {}


class ChainTester:
    def __init__(self, binary_path: str, arch):
        self.binary = Path(binary_path)
        if arch == "riscv":
            self.project = angr.Project(self.binary.as_posix(), arch=archinfo.ArchPcode("RISCV:LE:64:RV64GC"),
                                        engine=UberEnginePcode,
                                        auto_load_libs=False,
                                        load_options={'main_opts':{'base_addr': 0}}
                                        )
            self.project.arch.lr_offset = 8200
        else:  # aarch64
            self.project = angr.Project(self.binary.as_posix(), arch='AARCH64:LE:64:v8A',
                use_sim_procedures=False,
                # engine=UberEnginePcode,
                auto_load_libs=False,
                load_options={'main_opts':{'base_addr': 0}}
                )
            for adr in list(self.project._sim_procedures):  # REALLY don't use SimProcedures
                self.project.unhook(adr)

        self.analyze_regs = REGS[arch]

    def mem_read_hook(self, state: angr.SimState):
        # noinspection PyUnresolvedReferences
        addr, length, read_erg = state.inspect.mem_read_address, state.inspect.mem_read_length, state.inspect.mem_read_expr

        if (not all("Stack" in v for v in addr.variables)
                and not all("Stack" in v for v in read_erg.variables)
                and len(state.solver.eval_upto(read_erg, 2)) > 1):
            print(f"BREAK READ ({state.addr:#x}): {addr!r} -> {read_erg!r}"[:150])
            # return  # ENABLE MEM READ HERE
            raise angr.SimException(state.addr, f"Ignore this read: {addr!r} -> {read_erg!r}")

    def mem_write_hook(self, state: angr.SimState):
        # noinspection PyUnresolvedReferences
        addr, length, expr = state.inspect.mem_write_address, state.inspect.mem_write_length, state.inspect.mem_write_expr

        if len(state.solver.eval_upto(addr, 2)) > 1:
            print(f"BREAK WRITE: {expr!r} -> {addr!r}"[:150])
            # return  # ENABLE MEM WRITE HERE
            raise angr.SimException(state.addr, f"Ignore this write: {expr!r} -> {addr!r}")

    def validate_chain(self, chain: Sequence[int], regs: Iterable[str], final_jump=0xdeadbeef, pre_test=False, skip_reg_validation=False):
        global checked_gadgets

        # TODO gadgets might still be chainable
        # if len(chain) > 1:
        #     for gadget in chain:
        #         # single check
        #         t = checked_gadgets.get(gadget, None)
        #         if t is None:
        #             try:
        #                 self.validate_chain((gadget,), regs, pre_test=True, skip_reg_validation=True)
        #             except Exception as ex:
        #                 checked_gadgets[gadget] = False
        #                 assert False, f"New invalid gadget ({gadget:#x}) {ex!r}"
        #             checked_gadgets[gadget] = True
        #         elif t is False:
        #             # print("Known invalid gadget")
        #             assert False, f"Known invalid gadget {gadget}"

        # main check:
        out = ""

        def print(*args):
            nonlocal out
            out += " ".join(map(str, args)) + "\n"

        start = st = self.project.factory.blank_state(addr=chain[0])
        # st.options.add(angr.options.HIST)
        # HERE
        st.inspect.b('mem_read', angr.BP_AFTER, action=self.mem_read_hook)
        # st.inspect.b('mem_write', angr.BP_BEFORE, action=self.mem_write_hook)

        # BOPC test
        st.options.update(angr.sim_options.refs)

        for r in self.analyze_regs:
            reg: claripy.BV = getattr(st.regs, r)
            reg = claripy.BVS(f"Reg {r}", reg.size()).annotate(NameAnnotation(f"Reg {r}"))
            setattr(st.regs, r, reg)
        for i in range(-0x30, 0x400, st.arch.bits // 8):
            st.memory.store(st.regs.sp + i, claripy.BVS(f"Stack {i:#x}", st.arch.bits).annotate(NameAnnotation(f"Stack {i:#x}")).reversed)

        st.solver._solver.timeout = 250 * len(chain)  # ms
        sm = self.project.factory.simulation_manager(st, save_unconstrained=True)

        try:
            for gadget in chain:
                st.add_constraints(st.regs.pc == gadget)
                sm.explore(n=5, find_stash="unconstrained")
                st = sm.unconstrained[0]
                sm.stash()
                sm.move("unconstrained", "active")
        except IndexError:
            assert False, "Gadget not chainable"
        except KeyboardInterrupt:
            raise
            # print("SKIP chain")
            # assert False

        st.add_constraints(st.regs.pc == final_jump)
        assert st.satisfiable()

        if skip_reg_validation:
            return True

        # for h in st.history.parents:
        #     print(h)

        if not pre_test:  # assert regs on stack before adding constraints
            sp_pop = GadgetFinder.find_sp_pop(start, st)
            stack_read, moved, other, unchanged = GadgetFinder.classify_regs(start, st, regs)
            # print("Validation:", stack_read, moved, other, unchanged)
            if moved or other or unchanged:
                assert False, f"Regs not on stack ({moved=} {other=} {unchanged=})"

        for i, reg in enumerate(sorted(regs)):
            st.add_constraints(getattr(st.regs, reg) == int((f"4{i:x}" * 8)[:16], 16) & 0xffffffff)
        assert st.satisfiable()
        if pre_test:
            return True

        instructions = GadgetFinder.get_instructions(start, st)
        print("\n".join(map(str, instructions)))  # print instructions
        print("Instruction Count:", len(instructions))
        payload = st.solver.eval(start.stack_read(0, sp_pop + 0x80), cast_to=bytes)
        payload = payload[::-1]
        payload = p64(chain[0]) + payload
        print(payload.hex(), sorted(regs))
        print(sorted(st.solver.constraints, key=lambda x: "Reg" not in repr(x)))

        return out


def main(binary_path, arch=None, regs: Iterable[str] = None, num_regs: int = None, stop_first_found=False, only_validate=tuple()):
    binary = Path(binary_path)
    assert binary.exists()
    with binary.open("rb") as f:
        bin_hash = hashlib.sha256(f.read(), usedforsecurity=False).hexdigest()
    (binary,), = db.execute("SELECT bin_id FROM binaries WHERE sha256 = ?", [bin_hash]).fetchall()
    if arch is None:
        (arch,), = db.execute("SELECT arch FROM binaries WHERE bin_id = ?", [binary]).fetchall()

    if regs is None:
        if arch == "riscv":
            regs = {f"a{i}" for i in range(num_regs)}
        else:
            regs = {f"x{i}" for i in range(num_regs)}
    else:
        assert num_regs is None
        if arch == "riscv":
            assert "x" not in "".join(regs)
        else:
            assert "a" not in "".join(regs)

    if only_validate:
        print(_worker(binary_path, arch, only_validate, regs))
        return

    stop_after = 1000
    for chain in find_next_gadget(binary_path, binary, arch, regs):
        # for chain in find_next_gadget(binary_path, binary, arch, target_regs=regs, regs={"x0"}, gadgets=(4914332, 4350128)):
        print("Testing", list(map(hex, chain)))
        result = _worker(binary_path, arch, chain, regs)
        if result:
            print(result)
            stop_after -= 1
            if stop_after <= 0:
                return
            if stop_first_found:
                return


def const_iter(a):
    while True:
        yield a


@functools.cache
def _init_worker(binary_path, arch):
    return ChainTester(binary_path, arch)


def _worker(binary_path, arch, chain, regs):
    try:
        result = _init_worker(binary_path, arch).validate_chain(chain, regs)
        print("CHAIN", chain)
        return result
    except Exception as ex:
        pass
        print(ex)


chain_suffix_tests = defaultdict(lambda: 0)
CHAIN_SUFFIX_ABORT = 20
CHAIN_SUFFIX_LEN = 1


def find_next_gadget(binary_path, binary, arch, target_regs, regs=None, gadgets=tuple(), depth=0):
    global chain_suffix_tests

    if regs is None:
        regs = target_regs
    if gadgets and target_regs <= regs:
        return

    early_aborts = 0
    for gadget in find_gadget_iter_cache(binary, regs):
        address, return_type, ra, pop_size, reg_stack_read, reg_moved, reg_other, solver_constraints, instructions, last_instr, last_instr_addr = \
            db.execute("SELECT address, return_type, ra, pop_size, reg_stack_read, reg_moved, reg_other, solver_constraints, instructions, last_instr, last_instr_addr "
                       "FROM gadgets WHERE `binary` = ? AND address = ?", [binary, gadget]).fetchone()
        regs_moved: dict = parse_moved(reg_moved)
        regs_stack = set(reg_stack_read.split(", "))
        regs2 = {v for k, v in regs_moved.items() if k in regs}
        unchanged = regs.difference(regs_moved).difference(regs_stack)
        regs2.update(unchanged)
        # print(f"Remaining ({depth}):", regs2)
        if not return_type.startswith(("Stack", "ra")):  # return_type.startswith(("a", "s", "t",)):
            regs2.add(return_type)
        # print(regs2)

        if len(gadgets) >= CHAIN_SUFFIX_LEN and chain_suffix_tests[gadgets[-CHAIN_SUFFIX_LEN:]] > CHAIN_SUFFIX_ABORT:
            print("Suffix Abort top", gadgets)
            return

        if regs2:
            if len(gadgets) + 1 < 6:  # SET MAX CHAIN LEN HERE
                first_try = True
                for chain in find_next_gadget(binary_path, binary, arch, target_regs, regs2, (gadget,) + gadgets, depth + 1):
                    if first_try:
                        first_try = False
                        start = time.monotonic()
                        try:
                            # full check
                            ChainTester(binary_path, arch).validate_chain((gadget,) + gadgets, target_regs, pre_test=True)
                            early_aborts = 0
                        except Exception as ex:
                            early_aborts += 1
                            print(f"Early abort {early_aborts}:", ex, (gadget,) + gadgets, "tested for:", target_regs)
                            if early_aborts >= 10:
                                print(f"{early_aborts} early aborts, dropping chain")
                                return

                            # suffix abort
                            if len(gadgets) >= CHAIN_SUFFIX_LEN:
                                chain_suffix_tests[gadgets[-CHAIN_SUFFIX_LEN:]] += 1
                                print("SUFFIX", gadgets[-CHAIN_SUFFIX_LEN:], chain_suffix_tests[gadgets[-CHAIN_SUFFIX_LEN:]])
                                if chain_suffix_tests[gadgets[-CHAIN_SUFFIX_LEN:]] > CHAIN_SUFFIX_ABORT:
                                    print("Suffix Abort", gadgets)
                                    return
                            break  # double break
                        finally:
                            duration = time.monotonic() - start
                            print("Validation time:", duration)

                    yield chain
                else:
                    continue  # double break
                break  # double break

            else:
                # print("Length limit reached", depth)
                pass
        else:
            try:
                # ChainTester(binary_path).validate_chain((gadget,) + gadgets, target_regs)
                yield (gadget,) + gadgets
            except Exception as ex:
                print(ex)
                # import traceback
                # traceback.print_exc()
                continue


def open_db(path: str):
    db = sqlite3.connect(path)
    db.create_function("regexp", 2, lambda r, s: bool(re.search(r, s)))
    return db


if __name__ == '__main__':
    import os
    import sys
    db = open_db("rop_analysis.db")
    path = sys.argv[1]
    num_args = int(sys.argv[2])
    assert os.path.exists(path)
    main(path, stop_first_found=True, num_regs=num_args)
    #main("binaries/tests/vm_rop", stop_first_found=True, num_regs=3)
