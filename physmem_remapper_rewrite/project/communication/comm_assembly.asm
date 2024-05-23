.code
extern exit_constructed_space:qword

asm_handler proc

	; Return normal execution
	jmp qword ptr [exit_constructed_space]
asm_handler endp

end