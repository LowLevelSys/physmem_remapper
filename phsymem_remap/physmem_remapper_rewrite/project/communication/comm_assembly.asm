.code
extern exit_constructed_space:qword
extern handler: proc

asm_handler proc

	cmp edx, 6969h
	jne call_orig_data_ptr

	; Allocate stack memory for our handler 
	; (Allocate quite some memory to account for msvc compiler stupidity)
	sub rsp, 40h
	call handler
	add rsp, 40h

	jmp call_handler

; Either the call came from our um, then just return normally (skip_orig_function)
call_handler:
	mov rax, 1h
	jmp qword ptr [exit_constructed_space]

; Or the call came from windows (ew), then call the orig data ptr (skip_handler_function)
call_orig_data_ptr:
	mov rax, 0DEADh
	jmp qword ptr [exit_constructed_space]
asm_handler endp


end