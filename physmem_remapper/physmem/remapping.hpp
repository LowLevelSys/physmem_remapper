#pragma once
#include "includes/includes.hpp"
#include "physmem_structs.hpp"
#include "physmem.hpp"

uint32_t get_free_pdpt_table_index(page_table_t* inst);
uint32_t get_free_pde_table_index(page_table_t* inst);
uint32_t get_free_pte_table_index(page_table_t* inst);

extern "C" uint64_t __read_rax(void);
extern "C" void __write_rax(uint64_t new_rax);
extern "C" void __pop_rax(void);
extern "C" void __push_rax(void);

bool log_paging_hierarchy(uint64_t va, paging_structs::cr3 target_cr3);
bool remap_outside_virtual_address(uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3);