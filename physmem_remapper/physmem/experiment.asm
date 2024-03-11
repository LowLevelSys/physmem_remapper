.code

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

end