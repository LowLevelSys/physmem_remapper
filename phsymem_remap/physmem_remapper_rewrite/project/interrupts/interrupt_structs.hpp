#pragma once
#include "../project_includes.hpp"

typedef enum {
    /**
     * Nonmaskable Interrupt.
     * Source: Generated externally by asserting the processor's NMI pin or
     *         through an NMI request set by the I/O APIC to the local APIC.
     * Error Code: No.
     */
    nmi = 0x00000002,
} exception_vector;

#pragma pack(push, 1)
typedef struct {
    uint16_t limit;
    uint64_t base_address;
} segment_descriptor_register_64;
#pragma pack(pop)

#pragma pack(push, 1)
struct trap_frame_t {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;

    uint64_t rip;
    uint64_t cs_selector;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss_selector;
};
#pragma pack(pop)

typedef struct {
    uint16_t offset_low;
    uint16_t segment_selector;
    union {
        struct {
            uint32_t interrupt_stack_table : 3;
            uint32_t must_be_zero_0 : 5;
            uint32_t type : 4;
            uint32_t must_be_zero_1 : 1;
            uint32_t descriptor_privilege_level : 2;
            uint32_t present : 1;
            uint32_t offset_middle : 16;
        };

        uint32_t flags;
    };
    uint32_t offset_high;
    uint32_t reserved;
} segment_descriptor_interrupt_gate_64;

typedef union {
    struct {
        uint64_t carry_flag : 1;
        uint64_t read_as_1 : 1;
        uint64_t parity_flag : 1;
        uint64_t reserved1 : 1;
        uint64_t auxiliary_carry_flag : 1;
        uint64_t reserved2 : 1;
        uint64_t zero_flag : 1;
        uint64_t sign_flag : 1;
        uint64_t trap_flag : 1;
        uint64_t interrupt_enable_flag : 1;
        uint64_t direction_flag : 1;
        uint64_t overflow_flag : 1;
        uint64_t io_privilege_level : 2;
        uint64_t nested_task_flag : 1;
        uint64_t reserved3 : 1;
        uint64_t resume_flag : 1;
        uint64_t virtual_8086_mode_flag : 1;
        uint64_t alignment_check_flag : 1;
        uint64_t virtual_interrupt_flag : 1;
        uint64_t virtual_interrupt_pending_flag : 1;
        uint64_t identification_flag : 1;
        uint64_t reserved4 : 42;
    };

    uint64_t flags;
} rflags;

#define IA32_STAR 0xC0000081