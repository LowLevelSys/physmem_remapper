.code

; Results are returned in rax, so no need to do anything
__read_rax proc
    ret
__read_rax endp

__read_rcx proc
    mov rax, rcx
    ret
__read_rcx endp

; Reads the curr tr reg into rax
_str proc
    str rax
    ret
_str endp

; Loads a new tr reg based on the first parameter in rcx
_ltr proc
    mov cx, cx
    ltr cx
    ret
_ltr endp

; Reads cs into rax
__read_cs proc
    mov  rax, cs
    ret
__read_cs endp

end