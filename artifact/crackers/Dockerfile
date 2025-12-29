FROM rust:1.83-bookworm AS crackers_builder
WORKDIR /crackers_build
COPY crackers ./crackers
RUN apt update && apt install -y libclang-dev libz3-dev
RUN cargo build --release --bin crackers --features="bin" --manifest-path /crackers_build/crackers/Cargo.toml

FROM debian:trixie
WORKDIR /tmp
ENV VERSION=11.2.1_PUBLIC
ENV GHIDRA_SHA=ce4db5117da0fbaf8f33863fec4f40902f754f06b68945a59fb1c0f9b1bc461c
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip

RUN apt update && apt install -y libz3-4 libssl3 ca-certificates unzip
ADD $GHIDRA_URL /tmp/ghidra.zip
RUN unzip /tmp/ghidra.zip
RUN mv /tmp/ghidra_11.2.1_PUBLIC /opt/ghidra
COPY --from=crackers_builder /crackers_build/crackers/target/release/crackers /usr/bin/crackers

RUN mkdir /expriment
WORKDIR /experiment
RUN apt-get install -y python3 python3-pip python-is-python3
RUN pip3 install --break-system-packages jinja2
RUN pip3 install --break-system-packages pwntools angrop
COPY facefeed.o facefeed.o
COPY templates templates
COPY run_facefeed.py run_facefeed.py
COPY run_mmap.py run_mmap.py
COPY run_execve.py run_execve.py
COPY utils.py utils.py
