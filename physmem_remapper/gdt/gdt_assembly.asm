.code

; Gets the current gdt base into rax
get_current_gdt_base proc
    push rdi

    sub rsp, 10h

    lea rdi, [rsp]
    sgdt [rdi]
    mov rax, [rdi+2]

    add rsp, 10h

    pop rdi 

    ret
get_current_gdt_base endp

; Returns the curr tr index in rax
get_tr_index proc
    sub rsp, 2h

    str word ptr[rsp]

    xor rax, rax
    mov ax, [rsp]
    shr rax, 3
    and rax, 0FFFh

    add rsp, 2h

    ret
get_tr_index endp

; Returns the curr tss descriptor address in rax
get_tss_descriptor proc
    call get_tr_index

    mov eax, eax
    imul eax, eax, 8

    push rdx
    mov rdx, rax

    call get_current_gdt_base 
    add rax, rdx

    pop rdx
   
    ret
get_tss_descriptor endp

; Type is passed in ecx
set_tss_descriptor_available proc
    call get_tss_descriptor
    
    push rdx
    mov edx, [rax + 4]
  
    and edx, 0FFFFF0FFh
    or edx, 900h
    
    mov [rax + 4], edx
    pop rdx

    ret
set_tss_descriptor_available endp

end