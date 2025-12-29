import angr
import angrop
from multiprocessing import cpu_count

proj = angr.Project("/bin/ls", load_options={'main_opts':{'base_addr': 0}})
rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
rop.find_gadgets(processes=cpu_count(), show_progress=True)
chain = rop.func_call(0xfacefeed, [0xdeadbeef, 0x40, 0x7b], needs_return=False)
chain.print_payload_code()

state = chain.concrete_exec_til_addr(0xfacefeed)
print("====== chain execution result =====")
print("PC:", state.ip)
print("RDI:", state.regs.rdi)
print("RSI:", state.regs.rsi)
print("RDX:", state.regs.rdx)
print()
