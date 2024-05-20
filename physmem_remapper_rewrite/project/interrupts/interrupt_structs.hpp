#pragma once
#include "../project_includes.hpp"

typedef enum {
    /**
     * #DE - Divide Error.
     * Source: DIV and IDIV instructions.
     * Error Code: No.
     */
    divide_error = 0x00000000,

    /**
     * #DB - Debug.
     * Source: Any code or data reference.
     * Error Code: No.
     */
    debug = 0x00000001,

    /**
     * Nonmaskable Interrupt.
     * Source: Generated externally by asserting the processor's NMI pin or
     *         through an NMI request set by the I/O APIC to the local APIC.
     * Error Code: No.
     */
    nmi = 0x00000002,

    /**
     * #BP - Breakpoint.
     * Source: INT3 instruction.
     * Error Code: No.
     */
    breakpoint = 0x00000003,

    /**
     * #OF - Overflow.
     * Source: INTO instruction.
     * Error Code: No.
     */
    overflow = 0x00000004,

    /**
     * #BR - BOUND Range Exceeded.
     * Source: BOUND instruction.
     * Error Code: No.
     */
    bound_range_exceeded = 0x00000005,

    /**
     * #UD - Invalid Opcode (Undefined Opcode).
     * Source: UD instruction or reserved opcode.
     * Error Code: No.
     */
    invalid_opcode = 0x00000006,

    /**
     * #NM - Device Not Available (No Math Coprocessor).
     * Source: Floating-point or WAIT/FWAIT instruction.
     * Error Code: No.
     */
    device_not_available = 0x00000007,

    /**
     * #DF - Double Fault.
     * Source: Any instruction that can generate an exception, an NMI, or an INTR.
     * Error Code: Yes (zero).
     */
    double_fault = 0x00000008,

    /**
     * #\## - Coprocessor Segment Overrun (reserved).
     * Source: Floating-point instruction.
     * Error Code: No.
     *
     * @note Processors after the Intel386 processor do not generate this exception.
     */
    coprocessor_segment_overrun = 0x00000009,

    /**
     * #TS - Invalid TSS.
     * Source: Task switch or TSS access.
     * Error Code: Yes.
     */
    invalid_tss = 0x0000000A,

    /**
     * #NP - Segment Not Present.
     * Source: Loading segment registers or accessing system segments.
     * Error Code: Yes.
     */
    segment_not_present = 0x0000000B,

    /**
     * #SS - Stack Segment Fault.
     * Source: Stack operations and SS register loads.
     * Error Code: Yes.
     */
    stack_segment_fault = 0x0000000C,

    /**
     * #GP - General Protection.
     * Source: Any memory reference and other protection checks.
     * Error Code: Yes.
     */
    general_protection = 0x0000000D,

    /**
     * #PF - Page Fault.
     * Source: Any memory reference.
     * Error Code: Yes.
     */
    page_fault = 0x0000000E,

    /**
     * #MF - Floating-Point Error (Math Fault).
     * Source: Floating-point or WAIT/FWAIT instruction.
     * Error Code: No.
     */
    x87_floating_point_error = 0x00000010,

    /**
     * #AC - Alignment Check.
     * Source: Any data reference in memory.
     * Error Code: Yes.
     */
    alignment_check = 0x00000011,

    /**
     * #MC - Machine Check.
     * Source: Model dependent machine check errors.
     * Error Code: No.
     */
    machine_check = 0x00000012,

    /**
     * #XM - SIMD Floating-Point Numeric Error.
     * Source: SSE/SSE2/SSE3 floating-point instructions.
     * Error Code: No.
     */
    simd_floating_point_error = 0x00000013,

    /**
     * #VE - Virtualization Exception.
     * Source: EPT violations.
     * Error Code: No.
     */
    virtualization_exception = 0x00000014,
} exception_vector;

#pragma pack(push, 1)
typedef struct {
    uint16_t limit;
    uint64_t base_address;
} segment_descriptor_register_64;
#pragma pack(pop)

#pragma pack(push, 1)
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

typedef struct
{
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t HandlerAddress;
    uint32_t JumpTarget;
} SCOPE_RECORD;

typedef struct
{
    uint32_t Count;
    SCOPE_RECORD ScopeRecords[1];
} SCOPE_TABLE;

#pragma warning(push)
#pragma warning(disable : 4200)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef union {
    uint8_t CodeOffset;
    uint8_t UnwindOp : 4;
    uint8_t OpInfo : 4;
    uint16_t FrameOffset;
} UNWIND_CODE;

typedef struct {
    uint8_t Version : 3;
    uint8_t Flags : 5;
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;
    uint8_t FrameRegister : 4;
    uint8_t FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];

    union {
        uint32_t ExceptionHandler;
        uint32_t FunctionEntry;
    };

    uint32_t ExceptionData[];
} UNWIND_INFO;
#pragma warning(pop)

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_EPILOG /* just a dummy (= */
} UNWIND_CODE_OPS;

typedef union {
    struct {
        uint64_t virtual_mode_extensions : 1;
        uint64_t protected_mode_virtual_interrupts : 1;
        uint64_t timestamp_disable : 1;
        uint64_t debugging_extensions : 1;
        uint64_t page_size_extensions : 1;
        uint64_t physical_address_extension : 1;
        uint64_t machine_check_enable : 1;
        uint64_t page_global_enable : 1;
        uint64_t performance_monitoring_counter_enable : 1;
        uint64_t os_fxsave_fxrstor_support : 1;
        uint64_t os_xmm_exception_support : 1;
        uint64_t usermode_instruction_prevention : 1;
        uint64_t linear_addresses_57_bit : 1;
        uint64_t vmx_enable : 1;
        uint64_t smx_enable : 1;
        uint64_t fsgsbase_enable : 1;
        uint64_t pcid_enable : 1;
        uint64_t os_xsave : 1;
        uint64_t key_locker_enable : 1;
        uint64_t smep_enable : 1;
        uint64_t smap_enable : 1;
        uint64_t protection_key_enable : 1;
        uint64_t control_flow_enforcement_enable : 1;
        uint64_t protection_key_for_supervisor_mode_enable : 1;
        uint64_t reserved2 : 39;
    };

    uint64_t flags;
} cr4;