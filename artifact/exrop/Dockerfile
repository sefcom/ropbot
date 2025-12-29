FROM ubuntu:24.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y git
RUN git clone https://github.com/JonathanSalwan/Triton /Triton && cd /Triton && git checkout e312eafcdf507d9aebd0f8a7daf2eb4c28a19d30

################## Build Triton, copied from its Dockerfile #########################
# libboost >= 1.83
# libpython >= 3.12
# llvm >= 16.0
RUN DEBIAN_FRONTEND="noninteractive" \
    apt install -y --no-install-suggests --no-install-recommends \
        build-essential \
        clang \
        curl \
        git \
        libboost-all-dev \
        libgmp-dev \
        libpython3-dev \
        libpython3-stdlib \
        llvm-16 \
        llvm-16-dev \
        ninja-build \
        pkg-config \
        python3-pip \
        python3-venv \
        tar && \
    apt clean

ENV VIRTUAL_ENV=/Triton-venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# cmake >= 3.20
# libz3 >= 4.13.0
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install \
        cmake \
        lief \
        meson \
        setuptools \
        unicorn
RUN python3 -m pip install z3-solver==4.13.0.0 # this is the only version that's compatible with both Triton and angr

# libcapstone >= 5.0.x
RUN echo "[+] Download, build and install Capstone" && \
    cd /tmp && \
    curl -s -o capstone-5.0.1.tar.gz -L https://github.com/aquynh/capstone/archive/5.0.1.tar.gz && \
    tar xf capstone-5.0.1.tar.gz && \
    cd ./capstone-5.0.1 && \
    CAPSTONE_ARCHS="arm aarch64 riscv x86" ./make.sh && \
    make install

# libbitwuzla >= 0.4.0
RUN echo "[+] Download, build and install Bitwuzla" && \
    cd /tmp && \
    git clone https://github.com/bitwuzla/bitwuzla.git && \
    cd bitwuzla && \
    python3 ./configure.py --shared && \
    cd build && \
    ninja -j$(nproc) install

RUN echo "[+] Build and install Triton" && \
    Z3_PATH=$(python -c "import site; print(f'{site.getsitepackages()[0]}/z3')") && \
    # Triton (LLVM for lifting; z3 or bitwuzla as SMT solver)
    cd /Triton && \
    mkdir /tmp/triton-build && \
    cd /tmp/triton-build && \
    cmake \
        -DLLVM_INTERFACE=ON \
        -DCMAKE_PREFIX_PATH=$(llvm-config-16 --prefix) \
        -DZ3_INTERFACE=ON \
        -DZ3_INCLUDE_DIRS=$Z3_PATH/include/ \
        -DZ3_LIBRARIES=$Z3_PATH/lib/libz3.so \
        -DBITWUZLA_INTERFACE=ON \
        -DBITWUZLA_INCLUDE_DIRS=/usr/local/include \
        -DBITWUZLA_LIBRARIES=/usr/local/lib/x86_64-linux-gnu/libbitwuzla.so \
        /Triton && \
    make -j$(nproc) && \
    make install

RUN echo "[+] Check Triton build" && \
    echo export "PATH=$VIRTUAL_ENV/bin:$PATH" >> /etc/bash.bashrc && \
    # Print z3 version.
    python3 -c "import z3; print('Z3 version:', z3.get_version_string())" && \
    # Next command fails if Triton has no z3 or bitwuzla support.
    python3 -c "from triton import *; ctx=TritonContext(ARCH.X86_64); ctx.setSolver(SOLVER.Z3); ctx.setSolver(SOLVER.BITWUZLA);"

####################################################

RUN python3 -m pip install ROPGadget
RUN git clone https://github.com/d4em0n/exrop /exrop && cd /exrop && git checkout 343eee05bd4b9d31db3e55a70a33893527225c84

RUN python3 -m pip install angrop
RUN python3 -m pip install pwntools

RUN mkdir /expriment
WORKDIR /experiment
ENV PYTHONPATH=/exrop
COPY run_facefeed.py run_facefeed.py
COPY run_mmap.py run_mmap.py
COPY run_execve.py run_execve.py
COPY run_dup.py run_dup.py
COPY utils.py utils.py
