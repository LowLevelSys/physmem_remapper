#pragma once
#include "../physmem/physmem.hpp"
#include "../physmem/remapping.hpp"
#include "../gdt/gdt.hpp"

#define SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE 0xE
#define NMI_HANDLER_VECTOR 0x2

#pragma pack(push, 1)
typedef union {
    __m128 flags;
    struct {
        uint64_t offset_low : 16;
        uint64_t segment_selector : 16;
        uint64_t ist_index : 3;
        uint64_t reserved_0 : 5;
        uint64_t gate_type : 5;
        uint64_t dpl : 2;
        uint64_t present : 1;
        uint64_t offset_middle : 16;
        uint64_t offset_high : 32;
        uint64_t reserved_1 : 32;
    };
} idt_entry_t;

union idt_addr_t {
    void* addr;
    struct {
        uint64_t offset_low : 16;
        uint64_t offset_middle : 16;
        uint64_t offset_high : 32;
    };
};

struct trap_frame_t {
    // general-purpose registers
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    // interrupt vector
    uint64_t vector;
};

struct idt_ptr_t {
    uint16_t limit;
    uint64_t base;
};
#pragma pack(pop)