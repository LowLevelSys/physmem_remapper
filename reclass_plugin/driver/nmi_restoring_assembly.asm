.data
stack_id qword 0deedh

.code

extern nmi_restoring:proc
extern NtUserGetCPD:qword

save_general_regs macro
	push rsp
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
	pop rsp
endm

asm_nmi_restoring proc
	
	save_general_regs

	; Pass a ptr to the struct as the first arg
    mov rcx, rsp

	sub rsp, 40h
    call nmi_restoring ; Loads info from the nmi info struct and restores rsp and recursively calls the target function again
	add rsp, 40h

	restore_general_regs

	; the c handler set up the stack for us to be just able to return
	ret
asm_nmi_restoring endp

asm_call_driver proc

	push qword ptr [stack_id]
	call qword ptr [NtUserGetCPD]
	add rsp, 8h

	ret
asm_call_driver endp

end