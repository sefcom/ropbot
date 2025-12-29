from python:3.11.11-bookworm

run apt-get update
run pip install --upgrade pip
run apt-get install -y git cmake

# not needed by arcanist, needed by the evaluation framework
# install angrop early to avoid angr messing with z3 and capstone
run pip install angrop
run pip install pwntools

# install btor and pysmt
## install btor, it cannot be installed using the arcanist branch
run git clone https://gitlab.inria.fr/nballuet/pysmt && git -C pysmt checkout 8aaf1d3309e7402db20fafd6075a9ce7142fed85
workdir /pysmt
run pip install -e .
run pip install cython
run echo y | pysmt-install --btor
## now switch to the arcanist branch
run git checkout arcanist && pip install -e .

# install arcanist
add arcanist.tar.gz /
add patch.txt /tmp/patch.txt
workdir /arcanist/
run git config --global --add safe.directory /arcanist
run git init && git add . && git apply /tmp/patch.txt
workdir /arcanist/libs
run cd base && pip install -e .
run cd binaryninja-translator && pip install -e .
run cd ropper-extractor && pip install -e .
run cd synthesizer && pip install -e .
workdir /arcanist
run pip install -e .

# warmup arcanist
run python arcanist_tools/benchmark.py -h > /dev/null
run pip install pyboolector==3.2.4.20240823.1

# setup binaryninja
add binaryninja.tar.gz /
run mkdir /root/.binaryninja
add license.txt /root/.binaryninja/license.dat

# setup the experiment
run mkdir /expriment
workdir /experiment
#add binaries.tar.gz /experiment/
add utils.py utils.py
add run_facefeed.py run_facefeed.py
add run_mmap.py run_mmap.py
add run_execve.py run_execve.py
add run_arm_facefeed.py run_arm_facefeed.py

# /binaryninja/bnpython3 /arcanist/arcanist_tools/extract.py binaries/nginx /tmp/gadgets
# python /arcanist/arcanist_tools/benchmark.py --strategy incremental --timeout 3600 --jobs 16 gadgets/ls.json 8 600 stack-func-call-3args
cmd ["bash"]
