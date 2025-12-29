from python:3.11.11-bookworm

#run apt-get update && apt-get install -y python3 python-is-python3 python3-pip
#run apt-get install -y python3-venv parallel sqlite3
run apt-get update && apt-get install -y parallel sqlite3
run pip install --upgrade pip
run pip install pwntools protobuf==5.28.2

#run python -m venv /opt/venv
#env PATH="/opt/venv/bin:${PATH}"

add archinfo.tar.gz /
add angr.tar.gz /
add angrop-ng.tar.gz /

run apt-get install -y make

run pip install cffi unicorn==2.0.1.post1
workdir /archinfo
run pip install -e .
run pip install pyvex==9.2.139 cle==9.2.139 claripy==9.2.139
workdir /angr
run pip install --no-build-isolation -e .
workdir /angrop-ng
run pip install -e .

run pip install regex pwntools ipython

run apt-get install -y vim

copy riscyrop /riscyrop
workdir /riscyrop
run pip install -r ./requirements.txt

run mkdir /expriment
workdir /experiment
copy utils.py utils.py
copy run.py run.py
copy riscyrop/chaining.py chaining.py
copy riscyrop/misc.py misc.py
copy riscyrop/schema.sql schema.sql
copy riscyrop/sqlite_thread.py sqlite_thread.py
copy riscyrop/find_gadgets.py find_gadgets.py
