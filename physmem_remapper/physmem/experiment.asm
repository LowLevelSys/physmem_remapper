.code

extern handler:proc

; Results are returned in rax, so no need to do anything
__read_rax proc public
    ret
__read_rax endp

__write_rax proc
    mov rax, rcx
    ret
__write_rax endp

__pop_rax proc
    pop rax
    ret
__pop_rax endp

__push_rax proc
    push rax
    ret
__push_rax endp

asm_recover_regs proc  
    pop rax       ; Retreive the cr3 value it was originally at
    mov cr3, rax  ; Restore the cr3 value
    mfence
    jmp handler 
asm_recover_regs endp  

end