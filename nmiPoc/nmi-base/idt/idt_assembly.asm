nmi_info_storage_t struct
    real_rip qword ?
    real_rax qword ?
nmi_info_storage_t ends

.data
nmi_info nmi_info_storage_t <>
interrupted_rip qword 0

.code

extern handle_nmi:proc

extern windows_nmi_handler:qword
extern rop_gadget:qword

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

; Gadget:
; In _guard_dispatch_icall
; .text:0000000140408140                 mov     [rsp+0], rax
; .text:0000000140408144                 retn
asm_nmi_handler proc
	
	save_general_regs

    ; Pass a ptr to the struct as the first arg
    mov rcx, rsp

	sub rsp, 20h
    call handle_nmi
	add rsp, 20h

	test rax, rax
    jz dont_use_gadget

	; If handle_nmi returned true, jump to use_gadget
	jmp use_gadget

; We have to hide rip gadget now
use_gadget:
	restore_general_regs

	push rbx
    lea rbx, nmi_info

    ; Save the interrupted rax
    mov [rbx + nmi_info_storage_t.real_rax], rax

    ; Save the interrupted rip
    mov rax, [rsp + 8h]
    mov [rbx + nmi_info_storage_t.real_rip], rax

	pop rbx

	; Set the stored rip to the rop gadget
	mov rax, rop_gadget
	mov [rsp], rax
	
	; Allocate 8 bytes on the interrupted stack for
	; our gadget.
    mov rax, [rsp + 18h]
    sub rax, 8
	mov [rsp + 18h], rax

	; Since the gadget currently is mov [rsp], rax
	; mov restoring rip into rax
	lea rax, restoring

	jmp qword ptr [windows_nmi_handler]
; Just call the windows nmi handler, nothing to worry about
dont_use_gadget:
	restore_general_regs

	jmp qword ptr [windows_nmi_handler]

; In a real nmi handler restore regs here
restoring:
	lea rax, nmi_info
	
	; Restore rip
	mov rax, [rax + nmi_info_storage_t.real_rip]
	mov interrupted_rip, rax

	; Restore rax
	mov rax, [rax + nmi_info_storage_t.real_rax]

	jmp qword ptr [interrupted_rip]
asm_nmi_handler endp

; Intristics
__read_cs proc
    mov  rax, cs
    ret
__read_cs endp

end