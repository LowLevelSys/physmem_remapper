.code

extern return_address_storage:qword 
extern global_returning_shellcode:qword

extern handler:proc

; Returns the current processor number in eax
asm_get_curr_processor_number proc
    mov rax, gs:[20h]
    mov eax, [rax+24h]
    ret
asm_get_curr_processor_number endp

asm_handler proc
    ; Preserve the orig register state
    push rdx
    push rax

    ; Calculate the byte offset
    call asm_get_curr_processor_number
    mov eax, eax
    imul rdx, rax, 8

    ; Backup the original return address into an intermediate storage
    mov rax, [rsp + 16] ; + 8 since we pushed rdx
    add rdx, return_address_storage
    mov [rdx], rax

    ; Restore the orig register state
    pop rax
    pop rdx

    ; Remove the original return address from the stack in order not to corrupt the stack
    sub rsp, 8

    ; Call our c handler
    call handler

    ; Remember to not corrrupt the stack
    add rsp, 8

    ; Preserve the orig register state
    push rdx
    push rax

    ; Do the same bs again
    call asm_get_curr_processor_number

    ; Calculate the byte offset

    mov eax, eax
    imul rdx, rax, 8

    ; Load the return address from our storage
    add rdx, return_address_storage
    mov rax, [rdx]

    mov [rsp + 16], rax

    ; Restore the orig register state
    pop rax
    pop rdx

    ; Then return back to normal execution by jumping to the returning shellcode
    jmp qword ptr [global_returning_shellcode]
asm_handler endp

end