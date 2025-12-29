.intel_syntax noprefix

.global _start

_start:
mov     rdi, 0xdeadbeef
mov     rsi, 0x40
mov     rdx, 0x7b
mov     rax, 0xfacefeed
jmp     rax
