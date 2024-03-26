#include "comm.hpp"
#include "shared.hpp"
#include "../idt/idt.hpp"

/*
    Full assembly function:

    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,08
    push rdx
    mov rdx,FFFFDB80848E4000
    lea rax,[rdx+rax]
    mov edx,cr3
    mov edx,edx
    mov [rax],rdx
    pop rdx
    mov rax,000000044FF81000
    mov cr3,eax
    mov rax,FFFF8F844A15D000
    invplg [rax]
    mfence 
    lock mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    push rax
    mov rdx,FFFFDB80848EA000
    lea rax,[rdx+rax]
    sgdt [rax]
    pop rax
    mov rdx,FFFFDB80848E7000
    lea rax,[rdx+rax]
    lgdt [rax]
    pop rdx
    sub rsp,02
    str word ptr [rsp]
    xor eax,eax
    mov ax,[rsp]
    shr rax,03
    and eax,00000FFF
    add rsp,02
    mov eax,eax
    imul eax,eax,08
    push rdx
    mov rdx,rax
    push rdi
    sub rsp,00000010
    lea rdi,[rsp]
    sgdt [rdi]
    mov rax,[rdi+02]
    add rsp,00000010
    pop rdi
    add rax,rdx
    pop rdx
    push rdx
    mov edx,[rax+04]
    and edx,FFFFF0FF
    or edx,00000900
    mov [rax+04],edx
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,02
    push rdx
    push rax
    mov rdx,FFFFDB80848F0000
    lea rax,[rdx+rax]
    str word ptr [rax]
    pop rax
    mov rdx,FFFFDB80848ED000
    lea rax,[rdx+rax]
    mov ax,[rax]
    mov ax,ax
    ltr ax
    pop rdx
    mov rax,FFFFDB8084BB2040
    sidt [rax]
    mov rax,FFFFDB8084BB2030
    lidt [rax]
    mov rax,FFFFDB8084BA87F0
    jmp rax

*/

// Gernate the main part of the gadget, which is writing to cr3 and forcing the page to be flushed
uint8_t* generate_execute_jump_gadget_start(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region) {
    uint32_t index = 0;
    // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
    // mov rax, gs:[20h]
    gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
    gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov eax, [rax+24h]
    gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // Clear the top 32 bits of rax to ensure proper address calculation
    // mov eax, eax
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // Calculate the byte offset of base (using processor_index * 8)
    // imul eax, eax, 10
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

    // push rdx
    gadget[index++] = 0x52;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_cr3_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // mov edx, cr3
    gadget[index++] = 0x0f; gadget[index++] = 0x20; gadget[index++] = 0xda;

    // mov edx, edx
    gadget[index++] = 0x89; gadget[index++] = 0xd2;

    // mov [rax], rdx
    gadget[index++] = 0x48; gadget[index++] = 0x89; gadget[index++] = 0x10;

    // pop rdx
    gadget[index++] = 0x5a;

    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *(uint64_t*)&gadget[index] = cr3_value;
    index += 8;

    // mov cr3, rax
    gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *(uint64_t*)&gadget[index] = (uint64_t)mem;
    index += 8;

    // invlpg [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x38;
    // mfence
    gadget[index++] = 0x0f; gadget[index++] = 0xae; gadget[index++] = 0xf0;

    return &gadget[index];
}

// Generate the gdt changing part of the gadget
uint8_t* generate_execute_jump_gadget_gdt(uint8_t* gadget, gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region) {
    uint32_t index = 0;

    // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
    // mov rax, gs:[20h]
    gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8b; gadget[index++] = 0x04;
    gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov eax, [rax+24h]
    gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // Clear the top 32 bits of rax to ensure proper address calculation
    // mov eax, eax
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // Calculate the byte offset of base (using processor_index * 10)
    // imul eax, eax, 10
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x0a;

    // push rdx
    gadget[index++] = 0x52;

    // push rax
    gadget[index++] = 0x50;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // sgdt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x00;

    // pop rax
    gadget[index++] = 0x58;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_ptrs;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // lgdt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

    // pop rdx
    gadget[index++] = 0x5a;

    return &gadget[index];
}
 
/*
    The intel manual specifies that a tr write can't occur with a descriptor being referenced that is marked as busy
    segment_descriptor_32* curr_tss = (segment_descriptor_32*)(curr_gdt.base + (__read_tr().index * 8));
    curr_tss->type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
*/
uint8_t* generate_tss_available_gadget(uint8_t* gadget) {
    uint32_t index = 0;

    // sub rsp, 2
    gadget[index++] = 0x48; gadget[index++] = 0x83; gadget[index++] = 0xec; gadget[index++] = 0x02;

    // str [rsp]
    gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0x0c; gadget[index++] = 0x24;

    // xor eax, eax
    gadget[index++] = 0x31; gadget[index++] = 0xc0;

    // mov ax, [rsp]
    gadget[index++] = 0x66; gadget[index++] = 0x8b; gadget[index++] = 0x04; gadget[index++] = 0x24;

    // shr rax, 3
    gadget[index++] = 0x48; gadget[index++] = 0xc1; gadget[index++] = 0xe8; gadget[index++] = 0x03;

    // and eax, 0FFF
    gadget[index++] = 0x25; gadget[index++] = 0xff; gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // add rsp, 2
    gadget[index++] = 0x48; gadget[index++] = 0x83; gadget[index++] = 0xc4; gadget[index++] = 0x02;

    // mov eax, eax to clear upper 32 bits
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // imul eax, eax, 8
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

    // push rdx
    gadget[index++] = 0x52;

    // mov rdx, rax
    gadget[index++] = 0x48; gadget[index++] = 0x89; gadget[index++] = 0xc2;

    // push rdi
    gadget[index++] = 0x57;

    // sub rsp, 16
    gadget[index++] = 0x48; gadget[index++] = 0x81; gadget[index++] = 0xEC; gadget[index++] = 0x10; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // lea rdi, [rsp]
    gadget[index++] = 0x48; gadget[index++] = 0x8d; gadget[index++] = 0x3c; gadget[index++] = 0x24;

    // sgdt [rdi]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x07;

    // mov rax, [rdi+2]
    gadget[index++] = 0x48; gadget[index++] = 0x8b; gadget[index++] = 0x47; gadget[index++] = 0x02;

    // add rsp, 16
    gadget[index++] = 0x48; gadget[index++] = 0x81; gadget[index++] = 0xc4; gadget[index++] = 0x10; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // pop rdi
    gadget[index++] = 0x5f;

    // add rax, rdx
    gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

    // pop rdx
    gadget[index++] = 0x5a;

    // push rdx
    gadget[index++] = 0x52;

    // mov edx, [rax + 4]
    gadget[index++] = 0x8b; gadget[index++] = 0x50; gadget[index++] = 0x04;

    // and edx, 0FFFFF0FFh
    gadget[index++] = 0x81; gadget[index++] = 0xe2; gadget[index++] = 0xff; gadget[index++] = 0xf0; gadget[index++] = 0xff; gadget[index++] = 0xff;
    
    // or edx, 0x900h
    gadget[index++] = 0x81; gadget[index++] = 0xca; gadget[index++] = 0x00; gadget[index++] = 0x09; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov [rax + 4], edx
    gadget[index++] = 0x89; gadget[index++] = 0x50; gadget[index++] = 0x04;

    // pop rdx
    gadget[index++] = 0x5a;

    return &gadget[index];
}

// Call generate_tss_available_gadget, store tr, and load the new tr
uint8_t* generate_execute_jump_gadget_tr(uint8_t* gadget, segment_selector* my_tr, segment_selector* my_tr_storing_region) {
    uint32_t index = 0;

    gadget = generate_tss_available_gadget(gadget);

    // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
    // mov rax, gs:[20h]
    gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8b; gadget[index++] = 0x04;
    gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov eax, [rax+24h]
    gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // Clear the top 32 bits of rax to ensure proper address calculation
    // mov eax, eax
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // Calculate the byte offset of base (using processor_index * 2)
    // imul eax, eax, 2
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x02;

    // push rdx
    gadget[index++] = 0x52;

    // push rax
    gadget[index++] = 0x50;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_tr_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // str [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0x08;

    // pop rax
    gadget[index++] = 0x58;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_tr;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // mov ax, [rax]
    gadget[index++] = 0x66; gadget[index++] = 0x8b; gadget[index++] = 0x00;

    // mov ax, ax
    gadget[index++] = 0x66; gadget[index++] = 0x8b; gadget[index++] = 0xc0;

    // ltr ax
    gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0xd8;

    // pop rdx
    gadget[index++] = 0x5a;

    return &gadget[index];
}

// Generate the idt changing part of the gadget
// Also there is no need for the idt to have multiple
// instances where we safe it to, because the id<t is
// consistent across cores in contrast to gdt, tr, idt and cr3
uint8_t* generate_execute_jump_gadget_idt(uint8_t* gadget, idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region) {
    uint32_t index = 0;

    // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
    // mov rax, gs:[20h]
    gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
    gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov eax, [rax+24h]
    gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // Clear the top 32 bits of rax to ensure proper address calculation
    // mov eax, eax
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // Calculate the byte offset of base (using processor_index * 10)
    // imul eax, eax, 10
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x0a;

    // push rdx
    gadget[index++] = 0x52;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_idt_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // sidt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x08;

    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *(uint64_t*)&gadget[index] = (uint64_t)my_idt;
    index += 8;

    // lidt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x18;

    // pop rdx
    gadget[index++] = 0x5a;

    return &gadget[index];
}

// Generate the jmp rax part of the gadget
uint8_t* generate_execute_jump_gadget_end(uint8_t* gadget, uint64_t jmp_address) {
    uint32_t index = 0;
    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *(uint64_t*)&gadget[index] = jmp_address;
    index += 8;

    // jmp rax
    gadget[index++] = 0xff; gadget[index++] = 0xe0;

    return &gadget[index];
}

// Generates shellcode which jumps to our handler
void generate_executed_jump_gadget(uint8_t* gadget, uint64_t* my_cr3_storing_region,
                                   void* mem, uint64_t jmp_address, 
                                   idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region, 
                                   gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region,
                                   segment_selector* my_tr, segment_selector* my_tr_storing_region) {

    // Generate the full gadget in parts to make it a bit more readable
    gadget = generate_execute_jump_gadget_start(gadget, mem, my_cr3_storing_region);
    gadget = generate_execute_jump_gadget_gdt(gadget, my_gdt_ptrs, my_gdt_storing_region);
    gadget = generate_execute_jump_gadget_tr(gadget, my_tr, my_tr_storing_region);
    gadget = generate_execute_jump_gadget_idt(gadget, my_idt, my_idt_storing_region);
    gadget = generate_execute_jump_gadget_end(gadget, jmp_address);
}

// Generates shellcode which will effectively just write to cr3
void generate_shown_jump_gadget(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region) {
    uint32_t index = 0;

    // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
    // mov rax, gs:[20h]
    gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
    gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov eax, [rax+24h]
    gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // Clear the top 32 bits of rax to ensure proper address calculation
    // mov eax, eax
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // Calculate the byte offset of base (using processor_index * 8)
    // imul eax, eax, 10
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

    // push rdx
    gadget[index++] = 0x52;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_cr3_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // mov edx, cr3
    gadget[index++] = 0x0f; gadget[index++] = 0x20; gadget[index++] = 0xda;

    // mov edx, edx
    gadget[index++] = 0x89; gadget[index++] = 0xd2;

    // mov [rax], rdx
    gadget[index++] = 0x48; gadget[index++] = 0x89; gadget[index++] = 0x10;

    // pop rdx
    gadget[index++] = 0x5a;

    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *(uint64_t*)&gadget[index] = cr3_value;
    index += 8;

    // mov cr3, rax
    gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *(uint64_t*)&gadget[index] = (uint64_t)mem;
    index += 8;

    // invlpg [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x38;
    // mfence
    gadget[index++] = 0x0f; gadget[index++] = 0xae; gadget[index++] = 0xf0;

    // ret
    gadget[index++] = 0xc3;
}

bool execute_tests(void) {
    orig_NtUserGetCPD_type handler = (orig_NtUserGetCPD_type)global_new_data_ptr;
    uint32_t flags;
    uint64_t dw_data;

    // Generate the validation keys
    generate_keys(flags, dw_data);

    command cmd;

    // First call it for a test run (;
    cmd.command_number = cmd_comm_test;
    handler((uint64_t)&cmd, flags, dw_data);

    if (!test_call) {
        dbg_log_communication("Failed to do a test call");
        return false;
    }

    // Then ensure our driver being mapped in our cr3
    cmd.command_number = cmd_ensure_mapping;
    handler((uint64_t)&cmd, flags, dw_data);

    return true;
}

bool init_communication(void) {
	physmem* instance = physmem::get_physmem_instance();

	if (!instance->is_inited()) {
		dbg_log_communication("Physmem instance not inited; Returning...");
		return false;
	}

    auto hwin32k = get_driver_module_base(L"win32k.sys");
    if (!hwin32k) {
        dbg_log_communication("Failed to get win32k.sys base address");
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log_communication("Win32k.sys at %p \n", hwin32k);
#endif // ENABLE_COMMUNICATION_LOGGING

    auto winlogon_eproc = get_eprocess("winlogon.exe");
    if(!winlogon_eproc) {
        dbg_log_communication("Failed to get winlogon.exe eproc");
        return false;
    }

    // We need to attach to winlogon.exe to read from win32k.sys...
    KAPC_STATE apc;
    KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

    // NtUserGetCPD
    // 48 83 EC 28 48 8B 05 99 02
    uint64_t pattern = search_pattern_in_section(hwin32k, ".text", "\x48\x83\xEC\x28\x48\x8B\x05\x99\x02", 9, 0x0);

    int* displacement_ptr = (int*)(pattern + 7);
    uint64_t target_address = pattern + 7 + 4 + *displacement_ptr;
    uint64_t orig_data_ptr = *(uint64_t*)target_address;

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log_communication("Pattern at %p", pattern);
    dbg_log_communication("Target .data ptr stored at %p", target_address);
    dbg_log_communication("Target .data ptr value %p \n", orig_data_ptr);
    dbg_log("\n");
#endif // ENABLE_COMMUNICATION_LOGGING

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);

    void* executed_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);
    void* shown_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);

    if (!executed_pool || !shown_pool)
        return false;

    crt::memset(executed_pool, 0, PAGE_SIZE);
    crt::memset(shown_pool, 0, PAGE_SIZE);

    generate_executed_jump_gadget((uint8_t*)executed_pool, cr3_storing_region,
                                   shown_pool, (uint64_t)handler, 
                                   &my_idt_ptr, idt_storing_regions, 
                                   gdt_ptrs, gdt_storing_region, 
                                   tr_ptrs, tr_storing_region);

    generate_shown_jump_gadget((uint8_t*)shown_pool, shown_pool, cr3_storing_region);
    
    // Map the c3 bytes instead of the cc bytes (Source is what will be displayed and Target is where the memory will appear)
    if (!remap_outside_virtual_address((uint64_t)executed_pool, (uint64_t)shown_pool, instance->get_kernel_cr3())) {
        dbg_log_communication("Failed to remap outside virtual address %p in my cr3 to %p", shown_pool, executed_pool);
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log_communication("Executed pool at %p", executed_pool);
    dbg_log_communication("Shown pool at %p \n", shown_pool);
    dbg_log("\n");
#endif

#ifdef ENABLE_COMMUNICATION_PAGING_LOGGING
    log_paging_hierarchy((uint64_t)shown_pool, global_kernel_cr3);
    dbg_log("\n");
    log_paging_hierarchy((uint64_t)shown_pool, instance->get_my_cr3());
    dbg_log("\n");
#endif // ENABLE_COMMUNICATION_PAGING_LOGGING


    // Store all the info in global variables
    global_orig_data_ptr = orig_data_ptr;
    global_new_data_ptr = (uint64_t)shown_pool; // points to our gadget
    global_data_ptr_address = (uint64_t*)target_address;
    orig_NtUserGetCPD = (orig_NtUserGetCPD_type)global_orig_data_ptr;

    
    // Try to execute all commands before exchanging the .data ptr
    if (!execute_tests()) {
        dbg_log_communication("Failed tests... Not proceeding");
        return false;
    }
    
    /*
    // Attach to winlogon.exe
    KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

    // Point it to our gadget
    *global_data_ptr_address = global_new_data_ptr;

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);
    */

    return true;
}