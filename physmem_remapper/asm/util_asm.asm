.code

; Returns the current processor number in eax
asm_get_curr_processor_number proc
    mov rax, gs:[20h]
    mov eax, [rax+24h]
    ret
asm_get_curr_processor_number endp

end