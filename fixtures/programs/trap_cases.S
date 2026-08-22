#ifndef CASE
#error "CASE must be defined"
#endif

#ifndef EXPECTED_CAUSE
#error "EXPECTED_CAUSE must be defined"
#endif

    .section .text.init
    .globl _start
_start:
    la t0, trap_handler
    csrw mtvec, t0

#if CASE == 2
    li t0, -1
    csrw pmpaddr0, t0
    li t0, 0x0f
    csrw pmpcfg0, t0
    la t0, user_illegal_csr
    csrw mepc, t0
    csrr t0, mstatus
    li t1, ~(3 << 11)
    and t0, t0, t1
    csrw mstatus, t0
    mret
user_illegal_csr:
    csrw satp, a0
#elif CASE == 3
    ebreak
#elif CASE == 4
    la t0, aligned_data
    addi t0, t0, 1
    ld t1, 0(t0)
#elif CASE == 5
    li t0, 0
    ld t1, 0(t0)
#elif CASE == 6
    la t0, aligned_data
    addi t0, t0, 1
    sd t1, 0(t0)
#elif CASE == 7
    li t0, 0
    sd t1, 0(t0)
#elif CASE == 11
    ecall
#else
#error "unsupported CASE"
#endif
    j fail

trap_handler:
    csrr t0, mcause
    li t1, EXPECTED_CAUSE
    bne t0, t1, fail
    li a0, 1
    j finish

fail:
    li a0, 3

finish:
    la t0, tohost
    sd a0, 0(t0)
1:
    j 1b

    .section .data
    .align 3
aligned_data:
    .dword 0x1122334455667788

    .section .tohost,"aw",@progbits
    .align 3
    .globl tohost
tohost:
    .dword 0
    .globl fromhost
fromhost:
    .dword 0
