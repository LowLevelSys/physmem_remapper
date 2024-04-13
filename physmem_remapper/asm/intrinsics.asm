.code

; Results are returned in rax, so no need to do anything
__read_rax proc public
    ret
__read_rax endp

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

__read_rip proc
    mov rax, [rsp] ; mov the ret address into rax
    ret
__read_rip endp

end