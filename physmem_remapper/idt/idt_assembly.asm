.code

extern handle_non_maskable_interrupt:proc

trap_frame struct
  ; general-purpose registers
  $rax qword ?
  $rcx qword ?
  $rdx qword ?
  $rbx qword ?
  $rbp qword ?
  $rsi qword ?
  $rdi qword ?
  $r8  qword ?
  $r9  qword ?
  $r10 qword ?
  $r11 qword ?
  $r12 qword ?
  $r13 qword ?
  $r14 qword ?
  $r15 qword ?

  ; interrupt vector
  $vector qword ?
trap_frame ends

__read_cs proc
    mov     rax, cs
    ret
__read_cs endp

asm_non_maskable_interrupt_handler proc

    push 2 ; interrupt vector (which is 2 for nmis)

    sub rsp, 78h ; = 120 in decimal

    ; gprs
    mov trap_frame.$rax[rsp], rax
    mov trap_frame.$rcx[rsp], rcx
    mov trap_frame.$rdx[rsp], rdx
    mov trap_frame.$rbx[rsp], rbx
    mov trap_frame.$rbp[rsp], rbp
    mov trap_frame.$rsi[rsp], rsi
    mov trap_frame.$rdi[rsp], rdi
    mov trap_frame.$r8[rsp],  r8
    mov trap_frame.$r9[rsp],  r9
    mov trap_frame.$r10[rsp], r10
    mov trap_frame.$r11[rsp], r11
    mov trap_frame.$r12[rsp], r12
    mov trap_frame.$r13[rsp], r13
    mov trap_frame.$r14[rsp], r14
    mov trap_frame.$r15[rsp], r15

    ; Pass a ptr to the struct as the first arg
    mov rcx, rsp

    ; call handle_non_maskable_interrupt
    sub rsp, 20h
    call handle_non_maskable_interrupt
    add rsp, 20h

    ; gprs
    mov rax, trap_frame.$rax[rsp]
    mov rcx, trap_frame.$rcx[rsp]
    mov rdx, trap_frame.$rdx[rsp]
    mov rbx, trap_frame.$rbx[rsp]
    mov rbp, trap_frame.$rbp[rsp]
    mov rsi, trap_frame.$rsi[rsp]
    mov rdi, trap_frame.$rdi[rsp]
    mov r8,  trap_frame.$r8[rsp]
    mov r9,  trap_frame.$r9[rsp]
    mov r10, trap_frame.$r10[rsp]
    mov r11, trap_frame.$r11[rsp]
    mov r12, trap_frame.$r12[rsp]
    mov r13, trap_frame.$r13[rsp]
    mov r14, trap_frame.$r14[rsp]
    mov r15, trap_frame.$r15[rsp]

    ; free the trap_frame
    add rsp, 78h ; = 120 in decimal

    ; pop the interrupt vector
    add rsp, 8

    iretq
asm_non_maskable_interrupt_handler endp

end