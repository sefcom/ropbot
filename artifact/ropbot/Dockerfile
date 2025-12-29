from python:3.12.10-bookworm

run apt-get update && apt-get upgrade -y
run pip install --upgrade pip

run apt-get install -y make
run apt-get install -y binutils-riscv64-linux-gnu
run pip install cffi unicorn==2.0.1.post1
run pip install pwntools protobuf==5.28.2

add archinfo.tar.gz /
add angr.tar.gz /

workdir /archinfo
run pip install setuptools==79.0.1
run pip install -e .
run pip install pyvex==9.2.139 cle==9.2.139 claripy==9.2.139
workdir /angr
run pip install --no-build-isolation -e .

add angrop-ng.tar.gz /
workdir /angrop-ng
run pip install -e .

run mkdir /expriment
workdir /experiment
run mkdir gadget_caches

copy run_facefeed.py run_facefeed.py
copy run_mmap.py run_mmap.py
copy run_execve.py run_execve.py
copy run_dup.py run_dup.py
copy run_riscyrop.py run_riscyrop.py
copy run_test.py run_test.py
copy utils.py utils.py
copy ablation ablation
