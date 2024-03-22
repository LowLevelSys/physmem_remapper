.code

; If there are two calls at the same time from different processes we are screwed
extern global_proc_cr3:qword

; C handler for the data ptr
extern handler:proc

; Results are returned in rax, so no need to do anything
__read_rax proc public
    ret
__read_rax endp

asm_recover_regs proc  
    pop global_proc_cr3  ; Retreive the cr3 value of the calling process
    jmp handler 
asm_recover_regs endp  

asm_get_curr_processor_number proc
    mov rax, gs:[20h]
    mov eax, [rax+24h]
    ret
asm_get_curr_processor_number endp

end