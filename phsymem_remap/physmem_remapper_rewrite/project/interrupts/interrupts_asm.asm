.code

asm_nmi_handler proc
	iretq
asm_nmi_handler endp

__readcs proc
	mov rax, cs
	ret
__readcs endp

_sti proc
	sti	
	ret
_sti endp

_cli proc
	cli
	ret
_cli endp	

end