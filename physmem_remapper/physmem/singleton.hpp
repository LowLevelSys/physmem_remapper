#pragma once
#include "includes/includes.hpp"

template <typename t>
t get_value_in_cr3(uint64_t target_memory, uint64_t cr3_value) {
    uint64_t curr_cr3 = __readcr3();

    _mm_lfence();
    __writecr3(cr3_value);
    _mm_lfence();

    // Flush TLB
    __invlpg(reinterpret_cast<void*>(target_memory));

    t value = *(t*)target_memory;

    _mm_lfence();
    __writecr3(curr_cr3);
    _mm_lfence();

    // Flush TLB again
    __invlpg(reinterpret_cast<void*>(target_memory));

    return value;
}

template <typename t>
t execute_under_cr3(func_sig func, uint64_t cr3_value) {
    uint64_t curr_cr3 = __readcr3();

    _mm_lfence();
    __writecr3(cr3_value);
    _mm_lfence();

    // Flush TLB again
    __invlpg(reinterpret_cast<void*>(func));

    // Execute the function pointed to by func
    t result = func();

    _mm_lfence();
    __writecr3(curr_cr3);
    _mm_lfence();

    // Flush TLB again
    __invlpg(reinterpret_cast<void*>(func));

    return result;
}