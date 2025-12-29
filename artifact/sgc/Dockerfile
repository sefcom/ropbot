FROM gcc:bookworm AS boolector
RUN apt update && apt install -y cmake
RUN git clone https://github.com/boolector/boolector.git
WORKDIR /boolector
RUN ./contrib/setup-picosat.sh
RUN ./contrib/setup-btor2tools.sh
RUN ./configure.sh --only-picosat && cd build && make

FROM debian:bookworm AS ghidra_builder
ARG GHIDRA_VERSION="11.0.3"
ARG GHIDRA_DATE="20240410"
ARG GHIDRA_SHA256="2462a2d0ab11e30f9e907cd3b4aa6b48dd2642f325617e3d922c28e752be6761"
WORKDIR /ghidra
ADD https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip /ghidra/ghidra.zip
RUN apt update && apt install -y unzip
RUN unzip /ghidra/ghidra.zip

FROM python:3.9-bookworm

RUN apt update && apt install -y git binutils g++ make default-jre default-jdk
RUN git clone https://github.com/RUB-SysSec/gadget_synthesis.git
WORKDIR /gadget_synthesis
RUN git checkout 6a92a37525aa9810146003906ab41b7eb8e9ce2d

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv ${VIRTUAL_ENV}
RUN sed -i 's/__import__("miasm").VERSION/"0.1"/g' lib/miasm/setup.py
RUN /opt/venv/bin/pip install -r requirements.txt
COPY --from=boolector /boolector/build/bin/boolector /usr/bin/boolector
COPY --from=ghidra_builder /ghidra/ghidra_11.0.3_PUBLIC /ghidra
RUN ln -s /ghidra/support/analyzeHeadless /usr/bin/ghidra-analyzeHeadless

# now install angr, the version with python3.9 is way too old
RUN apt-get install -y python3.11 python3.11-venv
RUN python3.11 -m venv /angr-venv
RUN /angr-venv/bin/pip install angrop
RUN /angr-venv/bin/pip install pwntools
ENV PATH="/angr-venv/bin:${PATH}"
RUN pip install jinja2

RUN mkdir /expriment
WORKDIR /experiment
COPY run_facefeed.py run_facefeed.py
COPY run_mmap.py run_mmap.py
COPY run_execve.py run_execve.py
COPY utils.py utils.py
COPY templates templates
