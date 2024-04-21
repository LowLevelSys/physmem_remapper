#include "shellcode_bakery.hpp"

typedef int int32_t;

namespace executed_gadgets {
    /*
    The intel manual specifies that a tr write can't occur with a descriptor being referenced that is marked as busy
    segment_descriptor_32* curr_tss = (segment_descriptor_32*)(curr_gdt.base + (__read_tr().index * 8));
    curr_tss->type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
    */
    uint8_t* generate_tss_available_gadget(uint8_t* gadget) {
        static const uint8_t precomputed_sequence[] = {
            0x48, 0x83, 0xEC, 0x02, // sub rsp, 2
            0x0F, 0x00, 0x0C, 0x24, // str [rsp]
            0x31, 0xC0,             // xor eax, eax
            0x66, 0x8B, 0x04, 0x24, // mov ax, [rsp]
            0x48, 0xC1, 0xE8, 0x03, // shr rax, 3
            0x25, 0xFF, 0x0F, 0x00, 0x00, // and eax, 0FFF
            0x48, 0x83, 0xC4, 0x02, // add rsp, 2
            0x89, 0xC0,             // mov eax, eax to clear upper 32 bits
            0x6B, 0xC0, 0x08,       // imul eax, eax, 8
            0x52,                   // push rdx
            0x48, 0x89, 0xC2,       // mov rdx, rax
            0x57,                   // push rdi
            0x48, 0x81, 0xEC, 0x10, 0x00, 0x00, 0x00, // sub rsp, 16
            0x48, 0x8D, 0x3C, 0x24, // lea rdi, [rsp]
            0x0F, 0x01, 0x07,       // sgdt [rdi]
            0x48, 0x8B, 0x47, 0x02, // mov rax, [rdi+2]
            0x48, 0x81, 0xC4, 0x10, 0x00, 0x00, 0x00, // add rsp, 16
            0x5F,                   // pop rdi
            0x48, 0x01, 0xD0,       // add rax, rdx
            0x5A,                   // pop rdx
            0x52,                   // push rdx
            0x8B, 0x50, 0x04,       // mov edx, [rax + 4]
            0x81, 0xE2, 0xFF, 0xF0, 0xFF, 0xFF, // and edx, 0FFFFF0FFh
            0x81, 0xCA, 0x00, 0x09, 0x00, 0x00, // or edx, 0x900h
            0x89, 0x50, 0x04,       // mov [rax + 4], edx
            0x5A                    // pop rdx
        };

        crt::memcpy(gadget, precomputed_sequence, sizeof(precomputed_sequence));
        uint32_t index = sizeof(precomputed_sequence);
        return &gadget[index];
    }


    namespace jump_handler {
        // Gernate the main part of the gadget, which is writing to cr3 and forcing the page to be flushed
        uint8_t* generate_execute_jump_gadget_cr3(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region) {
            uint32_t index = 0;

            // Precompiled sequence of instructions that are mostly static
            static const uint8_t instruction_sequence[] = {
                0xfa,                                   // cli
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00, // mov rax, gs:[20h]
                0x8b, 0x80, 0x24, 0x00, 0x00, 0x00,     // mov eax, [rax+24h]
                0x89, 0xC0,                             // mov eax, eax (clear upper 32 bits)
                0x6b, 0xc0, 0x08,                       // imul eax, eax, 8
                0x52,                                   // push rdx
                0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Mov rdx, imm64
                0x48, 0x01, 0xd0,                       // add rax, rdx
                0x0f, 0x20, 0xda,                       // mov rdx, cr3
                0x48, 0x89, 0x10,                       // mov [rax], rdx
                0x5a,                                   // pop rdx
                // Mov rax, imm64 (cr3_value, placeholder for now)
                0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0f, 0x22, 0xd8,                       // mov cr3, rax
                // Mov rax, imm64 (mem, placeholder for now)
                0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0f, 0x01, 0x38,                       // invlpg [rax]
                0x0f, 0xae, 0xf0                        // mfence
            };

            crt::memcpy(gadget, instruction_sequence, sizeof(instruction_sequence));

            *reinterpret_cast<uint64_t*>(&gadget[24]) = reinterpret_cast<uint64_t>(my_cr3_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[44]) = physmem::get_physmem_instance()->get_my_cr3().flags;
            *reinterpret_cast<uint64_t*>(&gadget[57]) = reinterpret_cast<uint64_t>(mem);

            index += sizeof(instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_execute_jump_gadget_gdt(uint8_t* gadget, gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region) {

            // Precompiled instruction sequence with placeholders
            static const uint8_t instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00, // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                   // mov eax, [rax+24h]
                0x89, 0xC0,                                           // mov eax, eax (clear upper 32 bits)
                0x48, 0x6B, 0xC0, 0x0A,                               // imul rax, rax, 10
                0x52,                                                 // push rdx
                0x50,                                                 // push rax
                // Placeholder for mov rdx, imm64 my_gdt_storing_region
                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                     // add rax, rdx
                0x0F, 0x01, 0x00,                                     // sgdt [rax]
                0x58,                                                 // pop rax
                // Placeholder for mov rdx, imm64 my_gdt_ptrs
                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                     // add rax, rdx
                0x0F, 0x01, 0x10,                                     // lgdt [rax]
                0x5A                                                  // pop rdx
            };

            crt::memcpy(gadget, instruction_sequence, sizeof(instruction_sequence));
            uint32_t index = sizeof(instruction_sequence);

            // Fill in the placeholders with the actual addresses
            *reinterpret_cast<uint64_t*>(&gadget[25]) = reinterpret_cast<uint64_t>(my_gdt_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[42]) = reinterpret_cast<uint64_t>(my_gdt_ptrs);

            return &gadget[index];
        }

        // Call generate_tss_available_gadget, store tr, and load the new tr
        uint8_t* generate_execute_jump_gadget_tr(uint8_t* gadget, segment_selector* my_tr, segment_selector* my_tr_storing_region) {

            gadget = generate_tss_available_gadget(gadget);

            // Precompiled instruction sequence with placeholders
            static const uint8_t instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00, // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                   // mov eax, [rax+24h]
                0x89, 0xC0,                                           // mov eax, eax (clear upper 32 bits)
                0x48, 0x6B, 0xC0, 0x02,                               // imul rax, rax, 2
                0x52,                                                 // push rdx
                0x50,                                                 // push rax
                // Placeholder for mov rdx, imm64 my_tr_storing_region
                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                     // add rax, rdx
                0x0F, 0x00, 0x08,                                     // str [rax]
                0x58,                                                 // pop rax
                // Placeholder for mov rdx, imm64 my_tr
                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                     // add rax, rdx
                0x66, 0x8B, 0x00,                                     // mov ax, [rax]
                0x66, 0x8B, 0xC0,                                     // mov ax, ax
                0x0F, 0x00, 0xD8,                                     // ltr ax
                0x5A                                                  // pop rdx
            };

            crt::memcpy(gadget, instruction_sequence, sizeof(instruction_sequence));
            uint32_t index = sizeof(instruction_sequence);

            // Fill in the placeholders with the actual addresses
            *reinterpret_cast<uint64_t*>(&gadget[25]) = reinterpret_cast<uint64_t>(my_tr_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[42]) = reinterpret_cast<uint64_t>(my_tr);

            return &gadget[index];
        }

        // Generate the idt changing part of the gadget
        uint8_t* generate_execute_jump_gadget_idt(uint8_t* gadget, idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region) {

            // Precompiled instruction sequence with placeholders for addresses
            static const uint8_t instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00, // mov rax, gs:[20h]
                0x8b, 0x80, 0x24, 0x00, 0x00, 0x00,                   // mov eax, [rax+24h]
                0x89, 0xC0,                                           // mov eax, eax (clear upper 32 bits)
                0x6b, 0xc0, 0x0a,                                     // imul eax, eax, 10
                0x52,                                                 // push rdx
                // Placeholder for mov rdx, imm64 my_idt_storing_region
                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                     // add rax, rdx
                0x0f, 0x01, 0x08,                                     // sidt [rax]
                // Placeholder for mov rax, imm64 my_idt
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0f, 0x01, 0x18,                                     // lidt [rax]
                0x5A                                                  // pop rdx
            };

            crt::memcpy(gadget, instruction_sequence, sizeof(instruction_sequence));
            uint32_t index = sizeof(instruction_sequence);

            // Fill in the placeholders with actual addresses
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(my_idt_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[39]) = reinterpret_cast<uint64_t>(my_idt);

            return &gadget[index];
        }

        // Generate the jmp rax part of the gadget
        uint8_t* generate_execute_jump_gadget_end(uint8_t* gadget, uint64_t jmp_address) {
     
            // Precompiled instruction sequence with placeholders for the jump address
            static const uint8_t instruction_sequence[] = {
                0xfb,                            // sti
                0x48, 0xB8,                      // mov rax, imm64 (placeholder for jump address)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xE0                       // jmp rax
            };

            crt::memcpy(gadget, instruction_sequence, sizeof(instruction_sequence));
            uint32_t index = sizeof(instruction_sequence);

            // Fill in the placeholder for the jump address
            *reinterpret_cast<uint64_t*>(&gadget[3]) = jmp_address;

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
            static const uint8_t restore_cr3_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x08,                                      // imul eax, eax, 8
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for my_cr3_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x48, 0x8B, 0x00,                                      // mov rax, [rax]
                0x0F, 0x22, 0xD8,                                      // mov cr3, rax
                0x5A                                                   // pop rdx
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, restore_cr3_instruction_sequence, sizeof(restore_cr3_instruction_sequence));

            // Insert the actual memory address of my_cr3_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(my_cr3_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_cr3_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_gdt(uint8_t* gadget, gdt_ptr_t* my_gdt_storing_region) {
            static const uint8_t restore_gdt_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x0A,                                      // imul eax, eax, 10
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for my_gdt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x10,                                      // lgdt [rax]
                0x5A                                                   // pop rdx
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, restore_gdt_instruction_sequence, sizeof(restore_gdt_instruction_sequence));

            // Insert the actual memory address of my_gdt_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(my_gdt_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_gdt_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_tr(uint8_t* gadget, segment_selector* my_tr_storing_region) {
            static const uint8_t restore_tr_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x02,                                      // imul eax, eax, 2
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for my_tr_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x66, 0x8B, 0x00,                                      // mov ax, [rax]
                0x66, 0x8B, 0xC0,                                      // mov ax, ax
                0x0F, 0x00, 0xD8,                                      // ltr ax
                0x5A                                                   // pop rdx
            };

            // First, we need to insert the TSS available gadget which sets up the TSS descriptor
            gadget = generate_tss_available_gadget(gadget);

            // Now, copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, restore_tr_instruction_sequence, sizeof(restore_tr_instruction_sequence));

            // Insert the actual memory address of my_tr_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(my_tr_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_tr_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_idt(uint8_t* gadget, idt_ptr_t* my_idt_storing_region) {
            static const uint8_t restore_idt_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x0A,                                      // imul eax, eax, 10
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for my_idt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x18,                                      // lidt [rax]
                0x5A                                                   // pop rdx
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, restore_idt_instruction_sequence, sizeof(restore_idt_instruction_sequence));

            // Insert the actual memory address of my_idt_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(my_idt_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_idt_instruction_sequence);

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
            static const uint8_t change_cr3_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x08,                                      // imul eax, eax, 8
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for cr3_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x20, 0xDA,                                      // mov rdx, cr3
                0x48, 0x89, 0x10,                                      // mov [rax], rdx
                0x5A,                                                  // pop rdx
                0x48, 0xB8,                                            // mov rax, imm64 (placeholder for cr3_value)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x22, 0xD8                                       // mov cr3, rax
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, change_cr3_instruction_sequence, sizeof(change_cr3_instruction_sequence));

            // Insert the actual memory addresses into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(address_space_switching_cr3_storing_region);
            uint64_t cr3_value = physmem::get_physmem_instance()->get_kernel_cr3().flags;
            *reinterpret_cast<uint64_t*>(&gadget[43]) = cr3_value;

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(change_cr3_instruction_sequence);

            return &gadget[index];
        }

        // Generate the gdt changing part of the gadget
        uint8_t* generate_change_gdt(uint8_t* gadget, gdt_ptr_t* kernel_gdt_storing_region, gdt_ptr_t* address_space_switching_gdt_storing_region) {
            static const uint8_t change_gdt_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x48, 0x6B, 0xC0, 0x0A,                                // imul rax, rax, 10
                0x52,                                                  // push rdx
                0x50,                                                  // push rax
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_gdt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x00,                                      // sgdt [rax]
                0x58,                                                  // pop rax
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for kernel_gdt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x10,                                      // lgdt [rax]
                0x5A                                                   // pop rdx
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, change_gdt_instruction_sequence, sizeof(change_gdt_instruction_sequence));

            // Insert the actual memory addresses into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[25]) = reinterpret_cast<uint64_t>(address_space_switching_gdt_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[42]) = reinterpret_cast<uint64_t>(kernel_gdt_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(change_gdt_instruction_sequence);

            return &gadget[index];
        }

        // Call generate_tss_available_gadget, store tr, and load the new tr
        uint8_t* generate_change_tr(uint8_t* gadget, segment_selector* kernel_tr_storing_region, segment_selector* address_space_switching_tr_storing_region) {
            // First call to prepare TSS as available
            gadget = generate_tss_available_gadget(gadget);

            // Static instruction sequence
            static const uint8_t change_tr_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x48, 0x6B, 0xC0, 0x02,                                // imul rax, rax, 2
                0x52,                                                  // push rdx
                0x50,                                                  // push rax
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_tr_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x00, 0x08,                                      // str [rax]
                0x58,                                                  // pop rax
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for kernel_tr_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x66, 0x8B, 0x00,                                      // mov ax, [rax]
                0x66, 0x8B, 0xC0,                                      // mov ax, ax
                0x0F, 0x00, 0xD8,                                      // ltr ax
                0x5A                                                   // pop rdx
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, change_tr_instruction_sequence, sizeof(change_tr_instruction_sequence));

            // Insert the actual memory addresses into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[25]) = reinterpret_cast<uint64_t>(address_space_switching_tr_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[42]) = reinterpret_cast<uint64_t>(kernel_tr_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(change_tr_instruction_sequence);

            return &gadget[index];
        }

        // Generate the idt changing part of the gadget
        uint8_t* generate_change_idt(uint8_t* gadget, idt_ptr_t* kernel_idt_storing_region, idt_ptr_t* address_space_switching_idt_storing_region) {
            // Precompiled sequence of instructions that are mostly static
            static const uint8_t change_idt_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x0A,                                      // imul eax, eax, 10
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_idt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x08,                                      // sidt [rax]
                0x48, 0xB8,                                            // mov rax, imm64 (placeholder for kernel_idt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x01, 0x18,                                      // lidt [rax]
                0x5A                                                   // pop rdx
            };

            // Copy the precompiled instruction sequence into the gadget buffer
            crt::memcpy(gadget, change_idt_instruction_sequence, sizeof(change_idt_instruction_sequence));

            // Insert the actual memory addresses into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(address_space_switching_idt_storing_region);
            *reinterpret_cast<uint64_t*>(&gadget[39]) = reinterpret_cast<uint64_t>(kernel_idt_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(change_idt_instruction_sequence);

            return &gadget[index];
        }

        // Generate the function calling part of the gadget
        uint8_t* generate_call_function(uint8_t* gadget, void* function_address) {
            // Static instruction sequence with a placeholder for the function address
            static const uint8_t call_function_instruction_sequence[] = {
                0x48, 0xB8,                  // mov rax, imm64 (placeholder for function address)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xD0                   // call rax
            };

            // Copy the static instruction sequence to the gadget buffer
            crt::memcpy(gadget, call_function_instruction_sequence, sizeof(call_function_instruction_sequence));

            // Set the function address in the placeholder position
            *reinterpret_cast<uint64_t*>(&gadget[2]) = reinterpret_cast<uint64_t>(function_address);

            // Calculate the index for the next insertion point after the current sequence
            uint32_t index = sizeof(call_function_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_cr3(uint8_t* gadget, uint64_t* address_space_switching_cr3_storing_region) {
            // Static instruction sequence with placeholders for dynamic addresses
            static const uint8_t restore_cr3_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x08,                                      // imul eax, eax, 8
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_cr3_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x48, 0x8B, 0x00,                                      // mov rax, [rax]
                0x0F, 0x22, 0xD8,                                      // mov cr3, rax
                0x5A                                                   // pop rdx
            };

            // Copy the static instruction sequence to the gadget buffer
            crt::memcpy(gadget, restore_cr3_instruction_sequence, sizeof(restore_cr3_instruction_sequence));

            // Insert the actual memory address of address_space_switching_cr3_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(address_space_switching_cr3_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_cr3_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_gdt(uint8_t* gadget, gdt_ptr_t* address_space_switching_gdt_storing_region) {
            static const uint8_t restore_gdt_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x0A,                                      // imul eax, eax, 10
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_gdt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x10,                                      // lgdt [rax]
                0x5A                                                   // pop rdx
            };

            // Copy the static instruction sequence to the gadget buffer
            crt::memcpy(gadget, restore_gdt_instruction_sequence, sizeof(restore_gdt_instruction_sequence));

            // Insert the actual memory address of address_space_switching_gdt_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(address_space_switching_gdt_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_gdt_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_tr(uint8_t* gadget, segment_selector* address_space_switching_tr_storing_region) {
            // Begin with the function to set the available TSS
            gadget = generate_tss_available_gadget(gadget);

            static const uint8_t restore_tr_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x02,                                      // imul eax, eax, 2
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_tr_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x66, 0x8B, 0x00,                                      // mov ax, [rax]
                0x66, 0x8B, 0xC0,                                      // mov ax, ax
                0x0F, 0x00, 0xD8,                                      // ltr ax
                0x5A                                                   // pop rdx
            };

            // Copy the static instruction sequence to the gadget buffer
            crt::memcpy(gadget, restore_tr_instruction_sequence, sizeof(restore_tr_instruction_sequence));

            // Insert the actual memory address of address_space_switching_tr_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(address_space_switching_tr_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_tr_instruction_sequence);

            return &gadget[index];
        }

        uint8_t* generate_restore_idt(uint8_t* gadget, idt_ptr_t* address_space_switching_idt_storing_region) {
            static const uint8_t restore_idt_instruction_sequence[] = {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00,  // mov rax, gs:[20h]
                0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                    // mov eax, [rax+24h]
                0x89, 0xC0,                                            // mov eax, eax (clear upper 32 bits)
                0x6B, 0xC0, 0x0A,                                      // imul eax, eax, 10
                0x52,                                                  // push rdx
                0x48, 0xBA,                                            // mov rdx, imm64 (placeholder for address_space_switching_idt_storing_region)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x01, 0xD0,                                      // add rax, rdx
                0x0F, 0x01, 0x18,                                      // lidt [rax]
                0x5A                                                   // pop rdx
            };

            // Copy the static instruction sequence into the gadget buffer
            crt::memcpy(gadget, restore_idt_instruction_sequence, sizeof(restore_idt_instruction_sequence));

            // Insert the actual memory address of address_space_switching_idt_storing_region into the instruction sequence
            *reinterpret_cast<uint64_t*>(&gadget[23]) = reinterpret_cast<uint64_t>(address_space_switching_idt_storing_region);

            // Calculate the next index position after the inserted sequence
            uint32_t index = sizeof(restore_idt_instruction_sequence);

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
        static const uint8_t shown_jump_gadget_sequence[] = {
            0xfa,                           // cli
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00, // mov rax, gs:[20h]
            0x8B, 0x80, 0x24, 0x00, 0x00, 0x00,                 // mov eax, [rax+24h]
            0x89, 0xC0,                                         // mov eax, eax (clear upper 32 bits)
            0x6B, 0xC0, 0x08,                                   // imul eax, eax, 8
            0x52,                                               // push rdx
            0x48, 0xBA,                                         // mov rdx, imm64 (placeholder for my_cr3_storing_region)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x01, 0xD0,                                   // add rax, rdx
            0x0F, 0x20, 0xDA,                                   // mov rdx, cr3
            0x48, 0x89, 0x10,                                   // mov [rax], rdx
            0x5A,                                               // pop rdx
            0x48, 0xB8,                                         // mov rax, imm64 (placeholder for cr3_value)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0F, 0x22, 0xD8,                                   // mov cr3, rax
            0x48, 0xB8,                                         // mov rax, imm64 (placeholder for mem)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0F, 0x01, 0x38,                                   // invlpg [rax]
            0x0F, 0xAE, 0xF0,                                   // mfence
            0xC3                                                // ret
        };

        // Copy the precompiled instruction sequence into the gadget buffer
        crt::memcpy(gadget, shown_jump_gadget_sequence, sizeof(shown_jump_gadget_sequence));

        // Insert the actual memory addresses into the placeholders
        *reinterpret_cast<uint64_t*>(&gadget[24]) = reinterpret_cast<uint64_t>(my_cr3_storing_region);
        *reinterpret_cast<uint64_t*>(&gadget[44]) = physmem::get_physmem_instance()->get_my_cr3().flags;
        *reinterpret_cast<uint64_t*>(&gadget[57]) = reinterpret_cast<uint64_t>(mem);
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