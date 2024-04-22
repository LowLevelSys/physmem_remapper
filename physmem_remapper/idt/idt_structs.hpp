#pragma once
#include "../physmem/physmem.hpp"
#include "../physmem/remapping.hpp"
#include "../gdt/gdt.hpp"

#define SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE 0xE

#define DIVIDE_ERROR 0x0
#define NMI_HANDLER 0x2
#define INVALID_OPCODE 0x6
#define PAGE_FAULT 0xE
#define GENERAL_PROTECTION 0xD

#define UNW_FLAG_EHANDLER  1

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

struct trap_frame_ecode_t {
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

    uint64_t ecode; // Is a dummy error code when the exception/interrupt doesn't provide one
    uint64_t rip;
    uint64_t cs_selector;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss_selector;
};

struct idt_ptr_t {
    uint16_t limit;
    uint64_t base;
};
#pragma pack(pop)

typedef struct
{
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 HandlerAddress;
    UINT32 JumpTarget;
} SCOPE_RECORD;

typedef struct
{
    UINT32 Count;
    SCOPE_RECORD ScopeRecords[1];
} SCOPE_TABLE;

typedef struct
{
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 UnwindData;
} RUNTIME_FUNCTION;

#pragma warning(push)
#pragma warning(disable : 4200)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef union
{
    UINT8 CodeOffset;
    UINT8 UnwindOp : 4;
    UINT8 OpInfo : 4;
    UINT16 FrameOffset;
} UNWIND_CODE;

typedef struct
{
    UINT8 Version : 3;
    UINT8 Flags : 5;
    UINT8 SizeOfProlog;
    UINT8 CountOfCodes;
    UINT8 FrameRegister : 4;
    UINT8 FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];

    union {
        UINT32 ExceptionHandler;
        UINT32 FunctionEntry;
    };

    UINT32 ExceptionData[];
} UNWIND_INFO;
#pragma warning(pop)