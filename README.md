# ropbot
`ropbot` is a fast and powerful gadget finder and ROP chain generator.
It introduces a new abstraction, named ROPBlock, in the ROP chain construction process, which makes ROP chain generation an easier task.
We solve the classic register setting ROP chain generation task using a novel graph search algorithm and reduce its complexity from exponential to O(n).
In practice, it outperforms all state-of-the-art works in their own benchmarks in terms of both capability and speed.
And it is the only tool that is proven to be scalable and work on large binaries such as `chromium` and `linux kernel`.

This repository contains the source code of `ropbot` and all the artifact needed to replicate the results described in the paper.

# Paper
We describe our design and findings in this paper

[__ropbot: Reimaging Code Reuse Attack Synthesis__](https://kylebot.net/papers/ropbot.pdf)

Kyle Zeng, Moritz Schloegel, Christopher Salls, Adam Doupé, Ruoyu Wang, Yan Shoshitaishvili, Tiffany Bao

*In Proceedings of the Network and Distributed System Security Symposium (NDSS), February 2026*,

# Demo

## gadget finding

## find execve chain

## container escape chain for the kernel

# Directories

This repo contains two directories:
* artifact: all the artifact needed to replicate the results described in the paper
* ropbot: the source code of `ropbot`
