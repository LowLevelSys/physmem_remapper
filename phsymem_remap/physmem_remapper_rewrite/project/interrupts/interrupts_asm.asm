.code

extern handle_nmi:proc
extern nmi_shellcode:proc

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

asm_nmi_handler proc
	save_general_regs

	; Pass a ptr to the struct as the first arg
    mov rcx, rsp

	sub rsp, 20h
    call handle_nmi
	add rsp, 20h

	restore_general_regs

	jmp qword ptr [nmi_shellcode]
asm_nmi_handler endp

__readcs proc
	mov rax, cs
	ret
__readcs endp

_sti proc
	sti	
	ret
_sti endp

_cli proc
	cli
	ret
_cli endp	

end