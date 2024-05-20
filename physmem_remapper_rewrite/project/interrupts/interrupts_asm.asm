.code

extern handle_ecode_interrupt:proc

save_general_regs macro
    push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
endm

restore_general_regs macro
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
endm

__readcs proc
	mov rax, cs
	ret
__readcs endp

asm_ecode_interrupt_handler proc

	save_general_regs

    ; Pass a ptr to the struct as the first arg
    mov rcx, rsp

	sub rsp, 20h
    call handle_ecode_interrupt
	add rsp, 20h

	restore_general_regs

	; Remember to remove the error code from the stack
	add rsp, 8

    iretq
asm_ecode_interrupt_handler endp

asm_no_ecode_interrupt_handler proc
	push 0 ; Push a dummy error code

	save_general_regs

    ; Pass a ptr to the struct as the first arg
    mov rcx, rsp

	sub rsp, 20h
    call handle_ecode_interrupt
	add rsp, 20h

	restore_general_regs

	; Remember to remove the error code from the stack
	add rsp, 8

    iretq
asm_no_ecode_interrupt_handler endp

end