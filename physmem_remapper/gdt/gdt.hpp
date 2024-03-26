#pragma once
#include "../physmem/physmem.hpp"
#include "../physmem/remapping.hpp"
	
#include "gdt_structs.hpp"

#include <ntimage.h>

bool init_gdt(void);

// Gdt info
inline gdt_ptr_t* gdt_ptrs;
inline gdt_ptr_t* gdt_storing_region;

// Tr info (used for replacing tss)
inline segment_selector* tr_ptrs;
inline segment_selector* tr_storing_region;

inline my_gdt_t my_gdt_state = { 0 };

uint64_t segment_base(gdt_ptr_t& gdtr, segment_selector selector);

// Assembly function declarations
extern "C" segment_selector _str(void);
extern "C" void _ltr(uint16_t tr);
extern "C" segment_selector __read_cs(void);

// Both are exported by the msvc compiler, but you need to declare them
extern "C" void _sgdt(void* gdtr);
extern "C" void _lgdt(void* gdtr);