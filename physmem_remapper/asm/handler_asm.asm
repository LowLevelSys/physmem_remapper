.code

extern global_returning_shellcode:qword
extern handler:proc

asm_handler proc

    ; Arguments are stored in rcx, edx and r8; No need to manipulate the stack etc.
    call handler

    ; Then return back to normal execution by jumping to the returning shellcode
    jmp qword ptr [global_returning_shellcode]
asm_handler endp

end