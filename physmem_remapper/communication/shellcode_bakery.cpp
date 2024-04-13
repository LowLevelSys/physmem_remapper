#include "shellcode_bakery.hpp"

typedef int int32_t;

namespace executed_gadgets {
    /*
    The intel manual specifies that a tr write can't occur with a descriptor being referenced that is marked as busy
    segment_descriptor_32* curr_tss = (segment_descriptor_32*)(curr_gdt.base + (__read_tr().index * 8));
    curr_tss->type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
    */
    uint8_t* generate_tss_available_gadget(uint8_t* gadget) {
        uint32_t index = 0;

        // sub rsp, 2
        gadget[index++] = 0x48; gadget[index++] = 0x83; gadget[index++] = 0xEC; gadget[index++] = 0x02;

        // str [rsp]
        gadget[index++] = 0x0F; gadget[index++] = 0x00; gadget[index++] = 0x0C; gadget[index++] = 0x24;

        // xor eax, eax
        gadget[index++] = 0x31; gadget[index++] = 0xC0;

        // mov ax, [rsp]
        gadget[index++] = 0x66; gadget[index++] = 0x8B; gadget[index++] = 0x04; gadget[index++] = 0x24;

        // shr rax, 3
        gadget[index++] = 0x48; gadget[index++] = 0xC1; gadget[index++] = 0xE8; gadget[index++] = 0x03;

        // and eax, 0FFF
        gadget[index++] = 0x25; gadget[index++] = 0xFF; gadget[index++] = 0x0F; gadget[index++] = 0x00; gadget[index++] = 0x00;

        // add rsp, 2
        gadget[index++] = 0x48; gadget[index++] = 0x83; gadget[index++] = 0xC4; gadget[index++] = 0x02;

        // mov eax, eax to clear upper 32 bits
        gadget[index++] = 0x89; gadget[index++] = 0xC0;

        // imul eax, eax, 8
        gadget[index++] = 0x6B; gadget[index++] = 0xC0; gadget[index++] = 0x08;

        // push rdx
        gadget[index++] = 0x52;

        // mov rdx, rax
        gadget[index++] = 0x48; gadget[index++] = 0x89; gadget[index++] = 0xC2;

        // push rdi
        gadget[index++] = 0x57;

        // sub rsp, 16
        gadget[index++] = 0x48; gadget[index++] = 0x81; gadget[index++] = 0xEC; gadget[index++] = 0x10; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

        // lea rdi, [rsp]
        gadget[index++] = 0x48; gadget[index++] = 0x8D; gadget[index++] = 0x3C; gadget[index++] = 0x24;

        // sgdt [rdi]
        gadget[index++] = 0x0F; gadget[index++] = 0x01; gadget[index++] = 0x07;

        // mov rax, [rdi+2]
        gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x47; gadget[index++] = 0x02;

        // add rsp, 16
        gadget[index++] = 0x48; gadget[index++] = 0x81; gadget[index++] = 0xC4; gadget[index++] = 0x10; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

        // pop rdi
        gadget[index++] = 0x5F;

        // add rax, rdx
        gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xD0;

        // pop rdx
        gadget[index++] = 0x5A;

        // push rdx
        gadget[index++] = 0x52;

        // mov edx, [rax + 4]
        gadget[index++] = 0x8B; gadget[index++] = 0x50; gadget[index++] = 0x04;

        // and edx, 0FFFFF0FFh
        gadget[index++] = 0x81; gadget[index++] = 0xE2; gadget[index++] = 0xFF; gadget[index++] = 0xF0; gadget[index++] = 0xFF; gadget[index++] = 0xFF;

        // or edx, 0x900h
        gadget[index++] = 0x81; gadget[index++] = 0xCA; gadget[index++] = 0x00; gadget[index++] = 0x09; gadget[index++] = 0x00; gadget[index++] = 0x00;

        // mov [rax + 4], edx
        gadget[index++] = 0x89; gadget[index++] = 0x50; gadget[index++] = 0x04;

        // pop rdx
        gadget[index++] = 0x5A;

        return &gadget[index];
    }


    namespace jump_handler {
        // Gernate the main part of the gadget, which is writing to cr3 and forcing the page to be flushed
        uint8_t* generate_execute_jump_gadget_cr3(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region) {
            uint32_t index = 0;

            // cli
            gadget[index++] = 0xfa;

            // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
            // mov rax, gs:[20h]
            gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
            gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // mov eax, [rax+24h]
            gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // Calculate the byte offset of base (using processor_index * 8)
            // imul eax, eax, 8
            gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

            // push rdx
            gadget[index++] = 0x52;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_cr3_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // mov rdx, cr3
            gadget[index++] = 0x0f; gadget[index++] = 0x20; gadget[index++] = 0xda;

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
            gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
            gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // mov eax, [rax+24h]
            gadget[index++] = 0x8B; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // Clear the top 32 bits of rax to ensure proper address calculation
            // mov eax, eax
            gadget[index++] = 0x89; gadget[index++] = 0xc0;

            // Calculate the byte offset of base (using processor_index * 10)
            // imul rax, rax, 10
            gadget[index++] = 0x48; gadget[index++] = 0x6b;
            gadget[index++] = 0xc0; gadget[index++] = 0x0a;

            // push rdx
            gadget[index++] = 0x52;

            // push rax
            gadget[index++] = 0x50;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // sgdt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x00;

            // pop rax
            gadget[index++] = 0x58;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_ptrs;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // lgdt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

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
            gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
            gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // mov eax, [rax+24h]
            gadget[index++] = 0x8B; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // Clear the top 32 bits of rax to ensure proper address calculation
            // mov eax, eax
            gadget[index++] = 0x89; gadget[index++] = 0xc0;

            // Calculate the byte offset of base (using processor_index * 2)
            // imul rax, rax, 2
            gadget[index++] = 0x48; gadget[index++] = 0x6b;
            gadget[index++] = 0xc0; gadget[index++] = 0x02;

            // push rdx
            gadget[index++] = 0x52;

            // push rax
            gadget[index++] = 0x50;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_tr_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // str [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0x08;

            // pop rax
            gadget[index++] = 0x58;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_tr;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;


            // mov ax, [rax]
            gadget[index++] = 0x66; gadget[index++] = 0x8B; gadget[index++] = 0x00;

            // mov ax, ax
            gadget[index++] = 0x66; gadget[index++] = 0x8B; gadget[index++] = 0xC0;

            // ltr ax
            gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0xD8;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        // Generate the idt changing part of the gadget
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

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

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

            // sti
            gadget[index++] = 0xfb;

            // mov rax, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xB8;
            *(uint64_t*)&gadget[index] = jmp_address;
            index += 8;

            // jmp rax
            gadget[index++] = 0xFF; gadget[index++] = 0xE0;

            return &gadget[index];
        }

        // Generates shellcode which jumps to our handler
        void generate_executed_jump_gadget(uint8_t* gadget, uint64_t* my_cr3_storing_region,
            void* mem, uint64_t jmp_address,
            idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region,
            gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region,
            segment_selector* my_tr, segment_selector* my_tr_storing_region) {

            // Generate the full gadget in parts to make it a bit more readable
            gadget = generate_execute_jump_gadget_cr3(gadget, mem, my_cr3_storing_region);
            gadget = generate_execute_jump_gadget_gdt(gadget, my_gdt_ptrs, my_gdt_storing_region);
            gadget = generate_execute_jump_gadget_tr(gadget, my_tr, my_tr_storing_region);
            gadget = generate_execute_jump_gadget_idt(gadget, my_idt, my_idt_storing_region);
            gadget = generate_execute_jump_gadget_end(gadget, jmp_address);
        }
    };

    namespace return_handler {

        uint8_t* generate_restore_cr3(uint8_t* gadget, uint64_t* my_cr3_storing_region) {
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

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // mov rax, [rax]
            gadget[index++] = 0x48; gadget[index++] = 0x8b; gadget[index++] = 0x00;

            // mov cr3, rax
            gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        uint8_t* generate_restore_gdt(uint8_t* gadget, gdt_ptr_t* my_gdt_storing_region) {
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

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // lgdt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        uint8_t* generate_restore_tr(uint8_t* gadget, segment_selector* my_tr_storing_region) {
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

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_tr_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

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

        uint8_t* generate_restore_idt(uint8_t* gadget, idt_ptr_t* my_idt_storing_region) {
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

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // lidt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x18;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        void generate_return_gadget(uint8_t* gadget, uint64_t jump_address,
            uint64_t* my_cr3_storing_region,
            idt_ptr_t* my_idt_storing_region,
            gdt_ptr_t* my_gdt_storing_region,
            segment_selector* my_tr_storing_region) {

            // push rax
            *gadget = 0x50;
            gadget++;

            // cli
            *gadget = 0xfa;
            gadget++;

            // Assume these functions update 'gadget' correctly
            gadget = generate_restore_cr3(gadget, my_cr3_storing_region);
            gadget = generate_restore_gdt(gadget, my_gdt_storing_region);
            gadget = generate_restore_tr(gadget, my_tr_storing_region);
            gadget = generate_restore_idt(gadget, my_idt_storing_region);

            uint32_t index = 0;

            // sti
            gadget[index++] = 0xfb;

            // pop rax
            gadget[index++] = 0x58;

            // cmp eax, 0x1337
            gadget[index++] = 0x3d; gadget[index++] = 0x37;
            gadget[index++] = 0x13; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // je [rip + 6] (jump to the ret if we returned SKIP_ORIG_DATA_PTR)
            gadget[index++] = 0x74; gadget[index++] = 0x0C;

            // mov rax, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xB8;
            *(uint64_t*)&gadget[index] = jump_address;
            index += 8;

            // jmp rax
            gadget[index++] = 0xFF; gadget[index++] = 0xE0;

            // ret (this will be executed if eax was 0x1337)
            gadget[index++] = 0xc3;
        }
    };

    namespace gadget_util {
        // Gernate the main part of the gadget, which is writing to cr3 and forcing the page to be flushed
        uint8_t* generate_change_cr3(uint8_t* gadget, uint64_t* address_space_switching_cr3_storing_region) {
            uint32_t index = 0;
            // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
            // mov rax, gs:[20h]
            gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
            gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // mov eax, [rax+24h]
            gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // Calculate the byte offset of base (using processor_index * 8)
            // imul eax, eax, 8
            gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

            // push rdx
            gadget[index++] = 0x52;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_cr3_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // mov rdx, cr3
            gadget[index++] = 0x0f; gadget[index++] = 0x20; gadget[index++] = 0xda;

            // mov [rax], rdx
            gadget[index++] = 0x48; gadget[index++] = 0x89; gadget[index++] = 0x10;

            // pop rdx
            gadget[index++] = 0x5a;

            // mov rax, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xb8;
            uint64_t cr3_value = physmem::get_physmem_instance()->get_kernel_cr3().flags;
            *(uint64_t*)&gadget[index] = cr3_value;
            index += 8;

            // mov cr3, rax
            gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

            return &gadget[index];
        }

        // Generate the gdt changing part of the gadget
        uint8_t* generate_change_gdt(uint8_t* gadget, gdt_ptr_t* kernel_gdt_storing_region, gdt_ptr_t* address_space_switching_gdt_storing_region) {
            uint32_t index = 0;

            // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
            // mov rax, gs:[20h]
            gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
            gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // mov eax, [rax+24h]
            gadget[index++] = 0x8B; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // Clear the top 32 bits of rax to ensure proper address calculation
            // mov eax, eax
            gadget[index++] = 0x89; gadget[index++] = 0xc0;

            // Calculate the byte offset of base (using processor_index * 10)
            // imul rax, rax, 10
            gadget[index++] = 0x48; gadget[index++] = 0x6b;
            gadget[index++] = 0xc0; gadget[index++] = 0x0a;

            // push rdx
            gadget[index++] = 0x52;

            // push rax
            gadget[index++] = 0x50;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_gdt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // sgdt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x00;

            // pop rax
            gadget[index++] = 0x58;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)kernel_gdt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // lgdt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        // Call generate_tss_available_gadget, store tr, and load the new tr
        uint8_t* generate_change_tr(uint8_t* gadget, segment_selector* kernel_tr_storing_region, segment_selector* address_space_switching_tr_storing_region) {
            uint32_t index = 0;

            gadget = generate_tss_available_gadget(gadget);

            // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
            // mov rax, gs:[20h]
            gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
            gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // mov eax, [rax+24h]
            gadget[index++] = 0x8B; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

            // Clear the top 32 bits of rax to ensure proper address calculation
            // mov eax, eax
            gadget[index++] = 0x89; gadget[index++] = 0xc0;

            // Calculate the byte offset of base (using processor_index * 2)
            // imul rax, rax, 2
            gadget[index++] = 0x48; gadget[index++] = 0x6b;
            gadget[index++] = 0xc0; gadget[index++] = 0x02;

            // push rdx
            gadget[index++] = 0x52;

            // push rax
            gadget[index++] = 0x50;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_tr_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // str [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0x08;

            // pop rax
            gadget[index++] = 0x58;

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)kernel_tr_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;


            // mov ax, [rax]
            gadget[index++] = 0x66; gadget[index++] = 0x8B; gadget[index++] = 0x00;

            // mov ax, ax
            gadget[index++] = 0x66; gadget[index++] = 0x8B; gadget[index++] = 0xC0;

            // ltr ax
            gadget[index++] = 0x0f; gadget[index++] = 0x00; gadget[index++] = 0xD8;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        // Generate the idt changing part of the gadget
        uint8_t* generate_change_idt(uint8_t* gadget, idt_ptr_t* kernel_idt_storing_region, idt_ptr_t* address_space_switching_idt_storing_region) {
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
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_idt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // sidt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x08;

            // mov rax, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xb8;
            *(uint64_t*)&gadget[index] = (uint64_t)kernel_idt_storing_region;
            index += 8;

            // lidt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x18;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        // Generate the function calling part of the gadget
        uint8_t* generate_call_function(uint8_t* gadget, void* function_address) {
            uint32_t index = 0;

            // mov rax, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xb8;
            function_address_pointer = (uint64_t*)&gadget[index];
            *(uint64_t*)&gadget[index] = (uint64_t)function_address;
            index += 8;

            // call rax
            gadget[index++] = 0xff; gadget[index++] = 0xd0;
 
            return &gadget[index];
        }

        uint8_t* generate_restore_cr3(uint8_t* gadget, uint64_t* address_space_switching_cr3_storing_region) {
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
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_cr3_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // mov rax, [rax]
            gadget[index++] = 0x48; gadget[index++] = 0x8b; gadget[index++] = 0x00;

            // mov cr3, rax
            gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        uint8_t* generate_restore_gdt(uint8_t* gadget, gdt_ptr_t* address_space_switching_gdt_storing_region) {
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

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_gdt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // lgdt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        uint8_t* generate_restore_tr(uint8_t* gadget, segment_selector* address_space_switching_tr_storing_region) {
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

            // mov rdx, imm64
            gadget[index++] = 0x48; gadget[index++] = 0xba;
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_tr_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

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

        uint8_t* generate_restore_idt(uint8_t* gadget, idt_ptr_t* address_space_switching_idt_storing_region) {
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
            *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)address_space_switching_idt_storing_region;
            index += 8;

            // add rax, rdx
            gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

            // lidt [rax]
            gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x18;

            // pop rdx
            gadget[index++] = 0x5a;

            return &gadget[index];
        }

        // Arguments are supposed to already be on the stack / in the appropriate regs
        void generate_address_space_switch_call_function_gadget(uint8_t* gadget, uint64_t* address_space_switching_cr3_storing_region,
            void* function_address,
            idt_ptr_t* kernel_idt_storing_region, idt_ptr_t* address_space_switching_idt_storing_region,
            gdt_ptr_t* kernel_gdt_storing_region, gdt_ptr_t* address_space_switching_gdt_storing_region,
            segment_selector* kernel_tr_storing_region, segment_selector* address_space_switching_tr_storing_region) {
            // cli
            *gadget = 0xfa;
            gadget++;

            // Generate the full gadget in parts to make it a bit more readable
            gadget = generate_change_cr3(gadget, address_space_switching_cr3_storing_region);
            gadget = generate_change_gdt(gadget, kernel_gdt_storing_region, address_space_switching_gdt_storing_region);
            gadget = generate_change_tr(gadget, kernel_tr_storing_region, address_space_switching_tr_storing_region);
            gadget = generate_change_idt(gadget, kernel_idt_storing_region, address_space_switching_idt_storing_region);

            // sti
            *gadget = 0xfb;
            gadget++;

            // call whatever_function_you_want
            gadget = generate_call_function(gadget, function_address);

            // cli
            *gadget = 0xfa;
            gadget++;

            // push rax
            *gadget = 0x50;
            gadget++;

            gadget = generate_restore_cr3(gadget, address_space_switching_cr3_storing_region);
            gadget = generate_restore_gdt(gadget, address_space_switching_gdt_storing_region);
            gadget = generate_restore_tr(gadget, address_space_switching_tr_storing_region);
            gadget = generate_restore_idt(gadget, address_space_switching_idt_storing_region);

            // pop rax
            *gadget = 0x58;
            gadget++;

            // sti
            *gadget = 0xfb;
            gadget++;

            // ret
            *gadget = 0xc3;
        }


        void load_new_function_address_in_gadget(uint64_t new_function) {
            if(function_address_pointer)
                *function_address_pointer = new_function;
        }
    };
};

namespace shown_gadgets {
    // Generates shellcode which will effectively just write to cr3
    void generate_shown_jump_gadget(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region) {
        uint32_t index = 0;
        // cli
        gadget[index++] = 0xfa;

        // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
        // mov rax, gs:[20h]
        gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
        gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

        // mov eax, [rax+24h]
        gadget[index++] = 0x8b; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

        // Calculate the byte offset of base (using processor_index * 8)
        // imul eax, eax, 8
        gadget[index++] = 0x6b; gadget[index++] = 0xc0; gadget[index++] = 0x08;

        // push rdx
        gadget[index++] = 0x52;

        // mov rdx, imm64
        gadget[index++] = 0x48; gadget[index++] = 0xba;
        *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_cr3_storing_region;
        index += 8;

        // add rax, rdx
        gadget[index++] = 0x48; gadget[index++] = 0x01; gadget[index++] = 0xd0;

        // mov rdx, cr3
        gadget[index++] = 0x0f; gadget[index++] = 0x20; gadget[index++] = 0xda;

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

        // ret (return)
        gadget[index++] = 0xc3;
    }

};

/*
    Shown gadget:

    cli
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    imul eax,eax,08
    push rdx
    mov rdx,FFFFC00100AD9000
    add rax,rdx
    mov edx,cr3
    mov [rax],rdx
    pop rdx
    mov rax,000000044EB7F000
    mov cr3,eax
    mov rax,FFFFC0010A03A000
    invplg [rax]
    mfence
    lock ret
*/

/*
    Executed gadget:
        Executed gadget:

    cli
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    imul eax,eax,08
    push rdx
    mov rdx,FFFFC00100AD9000
    add rax,rdx
    mov edx,cr3
    mov [rax],rdx
    pop rdx
    mov rax,000000044EB7F000
    mov cr3,eax
    mov rax,FFFFC0010A03A000
    invplg [rax]
    mfence
    lock mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul rax,rax,0A
    push rdx
    push rax
    mov rdx,FFFFC0010167C000
    add rax,rdx
    sgdt [rax]
    pop rax
    mov rdx,FFFFC00101679000
    add rax,rdx
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
    imul rax,rax,02
    push rdx
    push rax
    mov rdx,FFFFC001020FF000
    add rax,rdx
    str word ptr [rax]
    pop rax
    mov rdx,FFFFC0010167F000
    add rax,rdx
    mov ax,[rax]
    mov ax,ax
    ltr ax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFC00101676000
    add rax,rdx
    sidt [rax]
    mov rax,FFFFC001008A50A0
    lidt [rax]
    pop rdx
    sti
    mov rax,FFFFC0010089D070
    jmp rax
*/

/*
    Function calling gadget:
    cli
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    imul eax,eax,08
    push rdx
    mov rdx,FFFFC00100876000
    add rax,rdx
    mov edx,cr3
    mov [rax],rdx
    pop rdx
    mov rax,00000000001AD000
    mov cr3,eax
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul rax,rax,0A
    push rdx
    push rax
    mov rdx,FFFFC00100867000
    add rax,rdx
    sgdt [rax]
    pop rax
    mov rdx,FFFFC00100864000
    add rax,rdx
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
    imul rax,rax,02
    push rdx
    push rax
    mov rdx,FFFFC0010086D000
    add rax,rdx
    str word ptr [rax]
    pop rax
    mov rdx,FFFFC0010086A000
    add rax,rdx
    mov ax,[rax]
    mov ax,ax
    ltr ax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFC00100873000
    add rax,rdx
    sidt [rax]
    mov rax,FFFFC00100870000
    lidt [rax]
    pop rdx
    sti
    mov rax,ntoskrnl.MmFreeContiguousMemory
    call rax
    cli
    push rax
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,08
    push rdx
    mov rdx,FFFFC00100876000
    add rax,rdx
    mov rax,[rax]
    mov cr3,eax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFC00100867000
    add rax,rdx
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
    mov rdx,FFFFC0010086D000
    add rax,rdx
    mov ax,[rax]
    mov ax,ax
    ltr ax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFC00100873000
    add rax,rdx
    lidt [rax]
    pop rdx
    pop rax
    sti
    ret

*/

/*
    Returning gadget: 
    push rax
    cli
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,08
    push rdx
    mov rdx,FFFFC00100AD9000
    add rax,rdx
    mov rax,[rax]
    mov cr3,eax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFC0010167C000
    add rax,rdx
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
    mov rdx,FFFFC001020FF000
    add rax,rdx
    mov ax,[rax]
    mov ax,ax
    ltr ax
    pop rdx
    mov rax,gs:[00000020]
    mov eax,[rax+00000024]
    mov eax,eax
    imul eax,eax,0A
    push rdx
    mov rdx,FFFFC00101676000
    add rax,rdx
    lidt [rax]
    pop rdx
    sti
    pop rax
    cmp eax,00001337
    je FFFFC001015DB10F
    mov rax,win32kfull.NtUserGetCPD
    jmp rax
    ret

*/