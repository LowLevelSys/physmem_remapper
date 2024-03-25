.code

; If there are two calls at the same time from different processes we are screwed
extern global_proc_cr3:qword

; C handler for the data ptr
extern handler:proc

asm_recover_regs proc  
    pop global_proc_cr3  ; Retreive the cr3 value of the calling process
    jmp handler 
asm_recover_regs endp  

; Returns the current processor number in eax
asm_get_curr_processor_number proc
    mov rax, gs:[20h]
    mov eax, [rax+24h]
    ret
asm_get_curr_processor_number endp

end