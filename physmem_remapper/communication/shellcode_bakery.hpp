#include "comm.hpp"
#include "shared.hpp"
#include "../idt/idt.hpp"

// Generates the real gadget that will effectively be executed ( - the instruction till write cr3)
void generate_executed_jump_gadget(uint8_t* gadget, uint64_t* my_cr3_storing_region,
    void* mem, uint64_t jmp_address,
    idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region,
    gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region,
    segment_selector* my_tr, segment_selector* my_tr_storing_region);

// Generates shellcode which will effectively just write to cr3
void generate_shown_jump_gadget(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region);

// Generates a gadget that will be used to return back to normal execution
// and which will allow us to not execute ANY instruction in our handler
// under the user proc cr3/idt/gdt/tr/tss
void generate_return_gadget(uint8_t* gadget,uint64_t jump_address,
    uint64_t* my_cr3_storing_region,
    idt_ptr_t* my_idt_storing_region,
    gdt_ptr_t* my_gdt_storing_region,
    segment_selector* my_tr_storing_region);