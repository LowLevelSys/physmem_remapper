#include "shellcode_bakery.hpp"

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

/*
    Full assembly function:

    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,08
    push rdx
    mov rdx,FFFFB780A511D000
    lea rax,[rdx+rax]
    mov edx,cr3
    mov edx,edx
    mov [rax],rdx
    pop rdx
    mov rax,0000000451FB3000
    mov cr3,eax
    mov rax,FFFF920170AF0000
    invplg [rax]
    mfence 
    lock mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    push rax
    mov rdx,FFFFB780A5126000
    lea rax,[rdx+rax]
    sgdt [rax]
    pop rax
    mov rdx,FFFFB780A5123000
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
    mov rdx,FFFFB780A512C000
    lea rax,[rdx+rax]
    str word ptr [rax]
    pop rax
    mov rdx,FFFFB780A5129000
    lea rax,[rdx+rax]
    mov ax,[rax]
    mov ax,ax
    ltr ax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFB780A5120000
    lea rax,[rdx+rax]
    sidt [rax]
    mov rax,FFFFB780A44CE048
    lidt [rax]
    pop rdx
    mov rax,FFFFB780A44C107D
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
    // imul eax, eax, 8
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
uint8_t* generate_execute_jump_gadget_end(uint8_t* gadget, uint64_t jump_address) {
    uint32_t index = 0;
    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *(uint64_t*)&gadget[index] = jump_address;
    index += 8;

    // jmp rax
    gadget[index++] = 0xff; gadget[index++] = 0xe0;

    return &gadget[index];
}

// Generates shellcode which jumps to our handler
void generate_executed_jump_gadget(uint8_t* gadget, uint64_t* my_cr3_storing_region,
    void* mem, uint64_t jump_address,
    idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region,
    gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region,
    segment_selector* my_tr, segment_selector* my_tr_storing_region) {

    // Generate the full gadget in parts to make it a bit more readable
    gadget = generate_execute_jump_gadget_start(gadget, mem, my_cr3_storing_region);
    gadget = generate_execute_jump_gadget_gdt(gadget, my_gdt_ptrs, my_gdt_storing_region);
    gadget = generate_execute_jump_gadget_tr(gadget, my_tr, my_tr_storing_region);
    gadget = generate_execute_jump_gadget_idt(gadget, my_idt, my_idt_storing_region);
    gadget = generate_execute_jump_gadget_end(gadget, jump_address);
}

uint8_t* restore_cr3(uint8_t* gadget, uint64_t* my_cr3_storing_region) {
    uint32_t index = 0;
    // push rax
    gadget[index++] = 0x50;

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
    // imul eax, eax, 8
    gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

    // push rdx
    gadget[index++] = 0x52;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_cr3_storing_region;
    index += 8;

    // lea rdx, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d; gadget[index++] = 0x14; gadget[index++] = 0x02;

    // mov rax, [rdx]
    gadget[index++] = 0x48; gadget[index++] = 0x8b; gadget[index++] = 0x02;

    // mov cr3, rax
    gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

    // pop rdx
    gadget[index++] = 0x5a;

    // pop rax
    gadget[index++] = 0x58;

    return &gadget[index];
}

uint8_t* restore_gdt(uint8_t* gadget, gdt_ptr_t* my_gdt_storing_region) {
    uint32_t index = 0;
    // push rax
    gadget[index++] = 0x50;

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

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // lgdt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

    // pop rdx
    gadget[index++] = 0x5a;

    // pop rax
    gadget[index++] = 0x58;

    return &gadget[index];
}

uint8_t* restore_tr(uint8_t* gadget, segment_selector* my_tr_storing_region) {
    uint32_t index = 0;
    // push rax
    *gadget = 0x50;
    gadget++;

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

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_tr_storing_region;
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

    // pop rax
    gadget[index++] = 0x58;

    return &gadget[index];
}

uint8_t* restore_idt_gadget(uint8_t* gadget, idt_ptr_t* my_idt_storing_region) {
    uint32_t index = 0;

    // push rax
    gadget[index++] = 0x50;

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

    // lidt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x18;

    // pop rdx
    gadget[index++] = 0x5a;

    // pop rax
    gadget[index++] = 0x58;

    return &gadget[index];
}

void generate_return_gadget(uint8_t* gadget, uint64_t jump_address,
    uint64_t* my_cr3_storing_region,
    idt_ptr_t* my_idt_storing_region,
    gdt_ptr_t* my_gdt_storing_region,
    segment_selector* my_tr_storing_region) {


    gadget = restore_cr3(gadget, my_cr3_storing_region);
    gadget = restore_gdt(gadget, my_gdt_storing_region);
    gadget = restore_tr(gadget, my_tr_storing_region);
    gadget = restore_idt_gadget(gadget, my_idt_storing_region);

    uint32_t index = 0;

    // cmp eax, 0x1337
    gadget[index++] = 0x3d; gadget[index++] = 0x37;
    gadget[index++] = 0x13; gadget[index++] = 0x00;
    gadget[index++] = 0x01;

    // jne [rip + 12]
    gadget[index++] = 0x75; gadget[index++] = 0x0c;

    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *(uint64_t*)&gadget[index] = jump_address;
    index += 8;

    // jmp rax
    gadget[index++] = 0xff; gadget[index++] = 0xe0;

    // ret (this will be executed if eax was 0x1337 == SKIP_ORIG_DATA_PTR)
    gadget[index++] = 0xc3;
}