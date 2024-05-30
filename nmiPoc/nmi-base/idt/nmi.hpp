#pragma once
#include "idt.hpp"
#include "idt_util.hpp"

extern "C" uint64_t rop_gadget = 0;
extern "C" uint64_t windows_nmi_handler = 0;

inline uint64_t caught_counter = 0;
inline nmi_interupt_info_t infos[MAX_STORED_NMI_INFO] = { 0 };

inline bool is_within_range(uint64_t target, uint64_t lower, uint64_t upper) {
    if (!lower || !upper || lower >= upper) {
        return false;
    }
    return (target > lower) && (target < upper);
}

// In here manipulate the stack to make it look legit
extern "C" bool handle_nmi(trap_frame_t* regs) {
    // we can use the gadget if cr3 == kernelcr3
    // other cr3's could lead to issues.
    // Implementing other cr3s is a to do
    bool can_use_gadget = __readcr3() == KERNEL_CR3;
    nmi_interupt_info_t& curr_info = infos[caught_counter];

    PKTHREAD thread = KeGetCurrentThread();

    // Safe info for logging
    curr_info.rip = regs->rip;
    curr_info.rsp = regs->rsp;
    curr_info.cr3 = __readcr3();

    curr_info.stack_base = (uint64_t)thread->StackBase;
    curr_info.stack_limit = (uint64_t)thread->StackLimit;

    curr_info.core_number = KeGetCurrentProcessorNumber();

    caught_counter++;
    return can_use_gadget;
}

inline bool init_nmi_handler(void) {
    windows_nmi_handler = (static_cast<uint64_t>(my_idt_table[NON_MASKABLE_INTERRUPT].offset_high) << 32) |
        (static_cast<uint64_t>(my_idt_table[NON_MASKABLE_INTERRUPT].offset_middle) << 16) |
        (my_idt_table[NON_MASKABLE_INTERRUPT].offset_low);

    uint64_t ntoskrnl_base = get_driver_module_base(L"ntoskrnl.exe");

    if (!ntoskrnl_base) {
        dbg_log("Failed to find ntoskrnl.exe");
        return false;
    }

    // _guard_dispatch_icall
    // mov [rsp], rax
    // ret
    const char pattern[] = "\x48\x89\x04\x24\xC3\x65\x80\x0C\x25\x56\x08\x00\x00\x01\x65\xF6\x04\x25\x56\x08\x00\x00\x02\x75\x05";

    rop_gadget = search_pattern_in_section(ntoskrnl_base, ".text", pattern, 25, 0x00);

    if (!rop_gadget) {
        dbg_log("Failed to find rop gadget");
        return false;
    }

    dbg_log("Found Ntoskrnl.exe at %p", ntoskrnl_base);
    dbg_log("Found Windows NMI handler at %p", windows_nmi_handler);
    dbg_log("Found rop gadget at %p", rop_gadget);

    my_idt_table[NON_MASKABLE_INTERRUPT] = create_interrupt_gate(asm_nmi_handler);

	return true;
}