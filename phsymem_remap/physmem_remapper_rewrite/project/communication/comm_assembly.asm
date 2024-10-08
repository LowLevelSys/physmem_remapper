.code

extern exit_constructed_space:qword
extern handler: proc
extern g_info_page:qword

;
;   Helper functions
;
get_proc_number proc
    push rbx
    push rcx
    push rdx

    xor  eax, eax            ; Clear eax
    mov  eax, 0Bh            ; Set eax to leaf 0x0B
    xor  ecx, ecx            ; Set ecx to 0 (subleaf 0)
    cpuid

    mov  eax, edx ; Save apic id

    pop  rdx
    pop  rcx
    pop  rbx

    ret
get_proc_number endp

; Assembly wrapper for the main handler
asm_handler proc
    
	; Allocate stack memory for our handler 
	; (Allocate quite some memory to account for msvc compiler stupidity)
    ; and align to a 16 byte boundary
	sub rsp, 40h
	call handler
	add rsp, 40h

    jmp qword ptr [exit_constructed_space]
asm_handler endp

end