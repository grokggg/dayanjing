.intel_syntax noprefix
.text
.globl ds_asm_stub
.type ds_asm_stub, @function

/* Windows x64 calling convention:
 *   RCX = a1   RDX = a2   R8 = a3   R9 = a4
 *   SSN passed on stack at [RSP + 0x28]
 *   Syscall ABI:  RCX -> R10, SSN -> RAX
 */
ds_asm_stub:
    mov     r10, rcx
    mov     eax, [rsp + 0x28]
    syscall
    ret
.size ds_asm_stub, .-ds_asm_stub
