.code
extern exit_constructed_space:qword
extern handler: proc

asm_handler proc

	call handler

	jmp qword ptr [exit_constructed_space]
asm_handler endp

end