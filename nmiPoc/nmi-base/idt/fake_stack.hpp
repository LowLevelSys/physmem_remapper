#pragma once
#include "idt.hpp"

extern "C" __declspec(dllimport) USHORT __stdcall RtlCaptureStackBackTrace(
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_to_(FramesToCapture, return) PVOID* BackTrace,
    _Out_opt_ PULONG BackTraceHash
);

// the actual allocation of the stack (points to the top of it)
extern "C" uint64_t * fake_stack = 0;

extern "C" uint64_t* fake_rbp = 0;
extern "C" uint64_t* fake_rsp = 0;

inline ULONG64 get_random_num_args() {
    ULONG64 seed = __rdtsc();
    int max_args = 3;
    return lcg_rand((ULONG64*)&seed) % (max_args + 1);
}

inline uint64_t generate_random_argument() {
    ULONG64 seed = __rdtsc();
    return (uint64_t)lcg_rand((ULONG64*)&seed);
}

// Creates a single fake stack frame, which looks valid
inline void create_single_stack_frame(uint64_t*& rsp, uint64_t*& rbp, uint64_t return_address) {
    if (!return_address) {
        dbg_log("Provided return address is zero");
        return;
    }

    ULONG64 num_args = get_random_num_args();

    // Ensure enough space is available in the stack before pushing data
    if (rsp - num_args - 2 < fake_stack) {
        dbg_log("Not enough space on stack to push arguments and control data");
        return;
    }

    for (ULONG64 i = 0; i < num_args; ++i) {
        *--rsp = generate_random_argument();
    }

    *--rsp = (uint64_t)rbp;
    *--rsp = return_address;
    rbp = rsp;
}

// Tries to walk the curr stack to check it's validity
// has to be called from asm to switch stacks maybe
void validate_curr_stack() {
    PHYSICAL_ADDRESS max_addr = { 0 };
    max_addr.QuadPart = MAXULONG64;

    uint64_t* storage = (uint64_t*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
    if (!storage)
        return;

    memset(storage, 0, KERNEL_STACK_SIZE);

    uint32_t captured_count = RtlCaptureStackBackTrace(
        0, // Start from the beginning of the stack
        50, // You won't ever get 0x200 frames though
        (void**)storage, // Storage
        NULL
    );

    dbg_log("Captured %d frames", captured_count);

    // Walk 50 frames at most
    for (uint32_t i = 0; i <= captured_count; i++)
    {
        uint64_t ret_rip = storage[i];

        is_ret_addr_valid(ret_rip);
    }

    MmFreeContiguousMemory(storage);
}

inline bool init_fake_stack() {
    PHYSICAL_ADDRESS max_addr = { 0 };
    max_addr.QuadPart = MAXULONG64;

    fake_stack = (uint64_t*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
    if (!fake_stack) {
        dbg_log("Failed to allocate fake stack");
        return false;
    }

    memset((void*)fake_stack, 0, KERNEL_STACK_SIZE);

    // Set up rsp and rbp
    fake_rsp = fake_stack + (KERNEL_STACK_SIZE / sizeof(uint64_t)) - 1;
    fake_rbp = fake_rsp;


    uint64_t ntoskrnl_base = get_driver_module_base(L"ntoskrnl.exe");

    if (!ntoskrnl_base) {
        dbg_log("Failed to find ntoskrnl.exe");
        return false;
    }

    // Create 15 valid frames, which should be more than enough
    for (uint64_t i = 0; i < 15; i++) {
        uint64_t exported_function = find_random_exported_function(ntoskrnl_base);
        if (!exported_function) 
            continue;

        create_single_stack_frame(fake_rsp, fake_rbp, exported_function);
    }

    validate_curr_stack();

    dbg_log("Successfully created valid stack");

    return true;
}