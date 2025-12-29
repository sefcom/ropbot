import argparse
import functools
import hashlib
import itertools
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Union, Iterable

import tqdm

from misc import NameAnnotation, REGS
from sqlite_thread import SQLiteThreadQueue

logging.basicConfig(level=logging.ERROR)

import archinfo
import claripy
import angr
from angr.calling_conventions import register_default_cc, register_syscall_cc
from angr.engines import UberEnginePcode
from angr.engines.pcode.lifter import PcodeDisassemblerInsn
from angr_platforms.risc_v import SimCCRISCV, SimRISCVSyscall

register_default_cc('RISCV:LE:64:default', SimCCRISCV)
register_syscall_cc('RISCV:LE:64:default', "default", SimRISCVSyscall)

PRINT = True


def to_signed(value, bits=64):
    if value & (1 << (bits - 1)):
        return ~(~value & ((1 << bits) - 1))
    return value


class GadgetFinder:
    def __init__(self, binary: Union[Path, str], arch=None, db_path="rop_analysis.db", skip_angr=False):
        binary = Path(binary)
        assert binary.exists()
        with binary.open("rb") as f:
            bin_hash = hashlib.sha256(f.read(), usedforsecurity=False).hexdigest()

        self.db = sqlite3.connect(db_path, timeout=30)
        self._init_db()
        if arch is not None:
            self.db.execute("INSERT OR IGNORE INTO binaries (sha256, name, arch) VALUES (?,?,?)", [bin_hash, binary.name, arch])
        else:
            arch, = self.db.execute("SELECT arch FROM binaries WHERE sha256 = ?", [bin_hash]).fetchone()
            assert arch
        self.bin_id, = self.db.execute("SELECT bin_id FROM binaries WHERE sha256 = ?", [bin_hash]).fetchone()
        self.db_t: SQLiteThreadQueue = None

        if skip_angr:
            return

        if arch == "riscv":
            self.project = angr.Project(binary.as_posix(), arch=archinfo.ArchPcode("RISCV:LE:64:RV64GC"),
                                        engine=UberEnginePcode,
                                        auto_load_libs=False,
                                        load_options={'main_opts':{'base_addr': 0}}
                                        )
            self.project.arch.lr_offset = 8200
        else:  # aarch64
            self.project = angr.Project(binary.as_posix(), arch='AARCH64:LE:64:v8A',
                use_sim_procedures=False,
                # engine=UberEnginePcode,
                auto_load_libs=False,
                load_options={'main_opts':{'base_addr': 0}}
                )
            for adr in list(self.project._sim_procedures):  # REALLY don't use SimProcedures
                self.project.unhook(adr)

        self.analyze_regs = REGS[arch]

        self._errors = {}

    def close(self):
        if self.db_t is not None:
            self.db_t.stop()
        self.db.close()

    def _init_db(self):
        self.db.executescript(Path(__file__).with_name("schema.sql").read_text())
        self.db.commit()

    def executable_ranges(self):
        for sec in self.project.loader.main_object.sections:
            if sec.is_executable:
                yield sec.min_addr, sec.max_addr

    def search_gadgets(self, start_addr: int = None, end_addr: int = None, single_gadget: Union[Iterable, int] = None):
        """Iterate binary and try all (aligned) addresses for ROP gadgets"""

        self.db.execute("UPDATE binaries SET last_run = CURRENT_TIMESTAMP WHERE bin_id = ?", [self.bin_id])
        self.db.commit()

        self.db_t = SQLiteThreadQueue("rop_analysis.db")  # TODO path from __init__
        self.db_t.start()

        if isinstance(single_gadget, Iterable):
            status = tqdm.tqdm(single_gadget, disable=not PRINT)
            for adr in status:
                status.set_postfix_str(hex(adr))
                self.try_gadget(adr)
            status.close()
            return
        elif single_gadget:
            return self.try_gadget(single_gadget)

        if start_addr:
            assert end_addr
            ranges = [(start_addr, end_addr)]
        else:
            ranges = self.executable_ranges()

        for start, end in ranges:
            if end <= start:
                return
            status = tqdm.tqdm(total=(end - start) // 2, disable=not PRINT)
            adr = start
            while adr < end:
                status.n = (adr - start) // 2
                status.update(0)
                status.set_postfix_str(hex(adr))

                adr = self.try_gadget(adr)
            status.close()

        self.db_t.stop()
        self.db_t = None

    def mem_read_hook(self, state: angr.SimState):
        # noinspection PyUnresolvedReferences
        addr, length, read_erg = state.inspect.mem_read_address, state.inspect.mem_read_length, state.inspect.mem_read_expr

        if (not all("Stack" in v for v in addr.variables)
                and not all("Stack" in v for v in read_erg.variables)
                and len(state.solver.eval_upto(read_erg, 2)) > 1):
            print(f"BREAK READ: {addr!r} -> {read_erg!r}"[:150])
            # return  # ENABLE MEM READ HERE
            raise angr.SimException(state.addr, f"Ignore this read: {addr!r} -> {read_erg!r}")

    def mem_write_hook(self, state: angr.SimState):
        # noinspection PyUnresolvedReferences
        addr, length, expr = state.inspect.mem_write_address, state.inspect.mem_write_length, state.inspect.mem_write_expr

        if len(state.solver.eval_upto(addr, 2)) > 1:
            print(f"BREAK WRITE: {expr!r} -> {addr!r}"[:150])
            # return  # ENABLE MEM WRITE HERE
            raise angr.SimException(state.addr, f"Ignore this write: {expr!r} -> {addr!r}")

    def try_gadget(self, adr: int) -> int:
        """Try if adr can be used as ROP gadget. Returns suggestion for next gadget address."""

        skip_block = False

        try:
            block = self.project.factory.block(adr)
            if not (block.disassembly and block.disassembly.insns):
                return adr + self.project.arch.instruction_alignment

            st = self.project.factory.blank_state(addr=adr)
            # st.options.add(angr.options.HIST)
            st.inspect.b('mem_read', angr.BP_AFTER, action=self.mem_read_hook)

            for r in self.analyze_regs:
                reg: claripy.BV = getattr(st.regs, r)
                reg = claripy.BVS(f"Reg {r}", reg.size()).annotate(NameAnnotation(f"Reg {r}"))
                setattr(st.regs, r, reg)
            for i in range(-0x30, 0x80, st.arch.bits // 8):
                st.memory.store(st.regs.sp + i, claripy.BVS(f"Stack {i:#x}", st.arch.bits).annotate(NameAnnotation(f"Stack {i:#x}")).reversed)

            st.solver._solver.timeout = 250  # ms
            sm = self.project.factory.simulation_manager(st, save_unconstrained=True)
            try:
                for _ in range(10):
                    sm.step()
                    sm.move('active', 'pruned',
                        lambda st: sum(len(st.project.factory.block(h.addr).disassembly.insns) for h in st.history.parents if h.addr) + len(st.project.factory.block(st.addr).disassembly.insns)
                                   > 500)  # prune extreme instruction lengths
                    sm.move('active', 'pruned', lambda st: len(st.solver.constraints) > 5)  # prune complex constraints

                    if sm.unconstrained:
                        for u in sm.unconstrained:
                            if not self.analyze_gadget(st, u):
                                skip_block = True
                        break
                    if not sm.active:
                        print(f"EXCEPTION No active states {sm!s}")
                        break
                else:
                    print(f"EXCEPTION Still active {sm!s}")
            except NotImplementedError as ex:
                msg = f"{type(ex).__name__}: {ex}"
                if msg in self._errors:
                    self._errors[msg] += 1
                else:
                    self._errors[msg] = 1
                    print(msg)  # TODO print always?
                return adr + 2
        except Exception as ex:
            # import traceback
            # traceback.print_exc()
            print(f"EXCEPTION {adr=:#x} {ex.__class__.__name__} {ex}")

        if skip_block:
            return block.addr + block.size
        else:
            return adr + self.project.arch.instruction_alignment

    def linear_disassembly(self, addr):
        while True:
            block = self.project.factory.block(addr)
            if not len(block.disassembly.insns):
                break
            yield from block.disassembly.insns
            addr = block.addr + block.size

    def is_intended(self, addr, threshold=50):
        if addr % self.project.arch.instruction_alignment != 0:
            return False
        if self.project.arch.name == 'AARCH64':
            return True

        assert threshold < 500, "is_intended threshold overflow"

        addr_threshold = max(addr - threshold, self.project.loader.find_section_containing(addr).min_addr)
        dis = self.linear_disassembly(addr_threshold)
        compressed = 0
        for i in dis:  # type: PcodeDisassemblerInsn
            if i.address >= addr:
                if compressed >= 2:
                    return i.address == addr
                else:
                    return self.is_intended(addr, threshold * 2)
            if compressed < 2:
                if i.size == 2:
                    compressed += 1
                else:
                    compressed = 0
        else:
            return self.is_intended(addr, threshold + 2)

    @staticmethod
    def find_return_type(start, uncon):
        if claripy.is_true(start.regs.lr == uncon.regs.ip):
            return "ra"

        if uncon.regs.ip.variables and all("Stack" in v for v in uncon.regs.ip.variables):
            if len(uncon.regs.ip.variables) == 1:
                return next(iter(uncon.regs.ip.variables)).split("_", 1)[0]
            else:
                return f"Stack <{uncon.regs.ip}>"

        for a in itertools.chain(uncon.regs.ip.annotations, uncon.regs.ip.variables):
            if isinstance(a, NameAnnotation) and a.name.startswith("Reg"):
                reg_str = a.name.split()[1]
            elif isinstance(a, str) and a.startswith("Reg"):
                reg_str = a.split(maxsplit=1)[1].split("_", 1)[0]
            else:
                continue

            r_a = start.regs.get(reg_str)
            if claripy.is_true(r_a == uncon.regs.ip):
                return reg_str
            if uncon.solver.unique(uncon.regs.ip - (r_a & ~1)):  # delete last bit due to alignment
                offset = uncon.solver.eval(uncon.regs.ip - r_a)
                if offset & 1 << uncon.regs.ip.length - 1:
                    offset = -((~offset + 1) & ((1 << uncon.regs.ip.length) - 1))
                return f"{reg_str}{offset:+#x}(≈)"

    @staticmethod
    def find_sp_pop(start, uncon):
        sp_pop = uncon.regs.sp - start.regs.sp
        if not sp_pop.concrete:
            return False
        return to_signed(uncon.solver.eval(sp_pop))

    @staticmethod
    def classify_regs(start, uncon, regs):
        unchanged = set()
        stack_read = set()
        other = set()
        moved = set()
        for r in regs:
            r_s: claripy.BV = start.regs.get(r)
            r_u: claripy.BV = uncon.regs.get(r)

            if (l := len(str(uncon.solver.constraints))) > 10_000:  # avoid constraint explosion
                raise RuntimeError(f"Constraint overflow ({r}, {l}).")

            if claripy.is_true(r_s == r_u):
                unchanged.add(r)
                continue

            if len(r_u.variables) == 1 and all("Stack" in v for v in r_u.variables) and len(uncon.solver.eval_upto(r_u, 256)) == 256:
                stack_read.add(r)
                continue

            cont = False
            for a in r_u.annotations:
                if isinstance(a, NameAnnotation) and a.name.startswith("Reg"):
                    reg_str = a.name.split()[1]
                    r_a = start.regs.get(reg_str)
                    if claripy.is_true(r_a == r_u):
                        if len(uncon.solver.eval_upto(r_u, 256)) == 256:
                            moved.add(f"{reg_str} -> {r}")
                            cont = True
                            # break
                    elif claripy.is_true(r_a[31:0] == r_u[31:0]):
                        if len(uncon.solver.eval_upto(r_u, 256)) == 256:
                            moved.add(f"{reg_str} -> {r}".replace("x", "w"))
                            cont = True

            if cont:
                continue

            if len(x := uncon.solver.eval_upto(r_u, 2)) == 1:
                other.add(f"{r}={x[0]:#x}")
                continue

            other.add(r)
        return stack_read, moved, other, unchanged

    @staticmethod
    def get_instructions(start, uncon):
        instr: list[angr.block.DisassemblerInsn] = []
        # dump instructions
        for h in list(uncon.history.parents)[1:]:
            instr.extend(start.project.factory.block(h.addr).disassembly.insns)
        else:
            instr.extend(start.project.factory.block(uncon.history.addr).disassembly.insns)
        return instr

    def analyze_gadget(self, start: angr.SimState, uncon: angr.SimState):
        """Analyze gadget for type of return and accessed registers"""

        return_type = self.find_return_type(start, uncon)

        if return_type is None:
            info = f"Unsupported return, {uncon.regs.ip=}, {uncon.regs.ip.annotations=}, {uncon.regs.ip.variables=}"
            PRINT and print(f"Gadget {start.addr=:#x}: {info}")
            self.db_t.add_query("REPLACE INTO gadget_errors (binary, address, info) VALUES (?,?,?)", [self.bin_id, start.addr, info])
            return False

        sp_pop = self.find_sp_pop(start, uncon)
        if sp_pop is False:
            info = "SP not concrete"
            PRINT and print(f"Gadget {start.addr=:#x}: {info}")
            self.db_t.add_query("REPLACE INTO gadget_errors (binary, address, info) VALUES (?,?,?)", [self.bin_id, start.addr, info])
            return False

        try:
            stack_read, moved, other, unchanged = self.classify_regs(start, uncon, self.analyze_regs)
        except RuntimeError as ex:
            info = f"{ex.args[0]} return={return_type}"
            PRINT and print(f"Gadget {start.addr=:#x}: {info}")
            self.db_t.add_query("REPLACE INTO gadget_errors (binary, address, info) VALUES (?,?,?)", [self.bin_id, start.addr, info])
            return False

        ra_info = "unknown"
        if claripy.is_true(uncon.regs.lr == start.regs.lr):
            ra_info = "unchanged"
        elif claripy.is_true(uncon.regs.lr == uncon.regs.ip):
            ra_info = "ip"
        else:
            ra_info = "not ip"

        try:
            intended = self.is_intended(start.addr)
        except Exception as ex:
            print("is_intended error:", ex)
            intended = None

        PRINT and print(f"Gadget {start.addr=:#x}, {intended=}, return={return_type}, ra={ra_info}, ip_c={uncon.ip_constraints}, pop={sp_pop:#x}, {stack_read=}, {other=}, {moved=}, solver_c={uncon.solver.constraints}")
        instr = self.get_instructions(start, uncon)

        self.db_t.add_query("REPLACE INTO gadgets (binary, address, address_hex, valid, intended, "
                            "return_type, ra, ip_constraints, pop_size, "
                            "reg_stack_read, reg_moved, reg_other, "
                            "solver_constraints, "
                            "instruction_count, instructions, "
                            "last_instr, last_instr_addr, last_instr_addr_hex) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            self.bin_id, start.addr, hex(start.addr), True, intended,
            return_type, ra_info, str(uncon.ip_constraints), sp_pop,
            ", ".join(stack_read), ", ".join(moved), ",".join(other),
            str(uncon.solver.constraints),
            len(instr), "\n".join(map(str, instr)),
            f"{instr[-1].mnemonic} {instr[-1].op_str}".strip(), instr[-1].address, hex(instr[-1].address),
        ])

        return True


@functools.cache
def arg_parse(args: tuple[str] = None):
    global PRINT
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--riscv", "-r", dest="arch", action="store_const", const="riscv")
    group.add_argument("--aarch64", "-a", dest="arch", action="store_const", const="aarch64")
    parser.add_argument("--silent", "-s", action="store_true", default=False)
    parser.add_argument("binary")
    parser.add_argument("chunk_size", default="0x100")
    parser.add_argument("chunk_nr", default="0")

    args = parser.parse_args(args)
    PRINT = not args.silent
    return args


# -----------------------------------------------------------

def main(argv=None):
    args = arg_parse(argv)

    binary = args.binary
    chunk_size = int(args.chunk_size, 16)
    chunk_nr = int(args.chunk_nr, 10)

    rop = GadgetFinder(binary, arch=args.arch)
    for start, end in rop.executable_ranges():
        while start < end:
            if chunk_nr > 0:
                start += chunk_size
                chunk_nr -= 1
            else:
                break
        if chunk_nr == 0:
            rop.search_gadgets(start, min(start + chunk_size, end))
            rop.close()
            return 0

    rop.close()
    print(int(args.chunk_nr, 10) - chunk_nr)
    return 1


if __name__ == '__main__':
    exit(main())
