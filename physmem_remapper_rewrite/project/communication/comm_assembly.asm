.code
extern exit_constructed_space:qword
extern handler: proc

asm_handler proc

	; Allocate stack memory for our handler 
	; (Allocate quite some memory to account for msvc compiler stupidity)
	sub rsp, 40h
	call handler
	add rsp, 40h

	jmp qword ptr [exit_constructed_space]
asm_handler endp

end