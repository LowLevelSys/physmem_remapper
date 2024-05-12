#include "physmem.hpp"

namespace physmem {
	cr3 constructed_cr3 = { 0 };
	cr3 kernel_cr3 = { 0 };

	constructed_page_tables page_tables = { 0 };
	bool initialized = false;

	project_status allocate_page_tables(void) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		max_addr.QuadPart = MAXULONG64;

		page_tables.pml4_table = (pml4e_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		memset(page_tables.pml4_table, 0, PAGE_SIZE);

		for (uint64_t i = 0; i < TABLE_COUNT; i++) {
			page_tables.pdpt_table[i] = (pdpte_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
			page_tables.pde_table[i] = (pde_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
			page_tables.pte_table[i] = (pte_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

			if (!page_tables.pdpt_table[i] ||
				!page_tables.pde_table[i] ||
				!page_tables.pte_table[i])
				return status_memory_allocation_failed;
			

			memset(page_tables.pdpt_table[i], 0, PAGE_SIZE);
			memset(page_tables.pde_table[i], 0, PAGE_SIZE);
			memset(page_tables.pte_table[i], 0, PAGE_SIZE);
		}

		return status_success;
	}

	project_status copy_kernel_page_tables(void) {
		pml4e_64* kernel_pml4_page_table = 0;

		kernel_cr3.flags = __readcr3();
		kernel_pml4_page_table = (pml4e_64*)win_get_virtual_address(kernel_cr3.address_of_page_directory << 12);

		if (!kernel_pml4_page_table)
			return status_address_translation_failed;

		memcpy(page_tables.pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

		return status_success;
	}

	project_status construct_my_page_tables(void) {
		page_tables.used_pml4e_slot = pt_helpers::find_free_pml4e_index(page_tables.pml4_table);

		if (!pt_helpers::is_index_valid(page_tables.used_pml4e_slot))
			return status_invalid_page_table_index;
		

		pml4e_64* memcpy_pml4_table = page_tables.pml4_table;
		pdpte_64* memcpy_pdpt_table = pt_manager::get_free_pdpt_table(&page_tables);
		pdpte_1gb_64* memcpy_pdpt_1gb_table = (pdpte_1gb_64*)memcpy_pdpt_table;
		pde_64* memcpy_pd_table = pt_manager::get_free_pd_table(&page_tables);
		pde_2mb_64* memcpy_pd_2mb_table = (pde_2mb_64*)memcpy_pd_table;
		pte_64* memcpy_pt_table = pt_manager::get_free_pt_table(&page_tables);

		if (!memcpy_pdpt_table || !memcpy_pd_table || !memcpy_pt_table) 
			return status_no_available_page_tables;
		
		uint64_t pdpt_pfn = win_get_physical_address(memcpy_pdpt_table) >> 12;
		uint64_t pd_pfn = win_get_physical_address(memcpy_pd_table) >> 12;
		uint64_t pt_pfn = win_get_physical_address(memcpy_pt_table) >> 12;

		if (!pdpt_pfn || !pd_pfn || !pt_pfn)
			return status_no_available_page_tables;
		

		// Pml4
		pml4e_64& free_pml4_slot = memcpy_pml4_table[page_tables.used_pml4e_slot];
		free_pml4_slot.present = true;
		free_pml4_slot.write = true;
		free_pml4_slot.page_frame_number = pdpt_pfn;

		// Pdpt
		uint32_t pdpt_idx = pt_helpers::find_free_pdpt_index(memcpy_pdpt_table);
		if (!pt_helpers::is_index_valid(pdpt_idx))
			return status_invalid_page_table_index;

		pdpte_64& free_pdpt_slot = memcpy_pdpt_table[pdpt_idx];
		free_pdpt_slot.present = true;
		free_pdpt_slot.write = true;
		free_pdpt_slot.page_frame_number = pd_pfn;

		uint32_t pdpt_1gb_idx = pt_helpers::find_free_pdpt_index(memcpy_pdpt_table);
		if (!pt_helpers::is_index_valid(pdpt_1gb_idx))
			return status_invalid_page_table_index;

		pdpte_1gb_64& free_pdpt_1gb_slot = memcpy_pdpt_1gb_table[pdpt_1gb_idx];
		free_pdpt_1gb_slot.present = true;
		free_pdpt_1gb_slot.write = true;
		free_pdpt_1gb_slot.large_page = true;

		// Pd
		uint32_t pd_idx = pt_helpers::find_free_pd_index(memcpy_pd_table);
		if (!pt_helpers::is_index_valid(pd_idx))
			return status_invalid_page_table_index;

		pde_64& free_pd_slot = memcpy_pd_table[pdpt_idx];
		free_pd_slot.present = true;
		free_pd_slot.write = true;
		free_pd_slot.page_frame_number = pt_pfn;

		uint32_t pd_2mb_idx = pt_helpers::find_free_pd_index(memcpy_pd_table);
		if (!pt_helpers::is_index_valid(pd_2mb_idx))
			return status_invalid_page_table_index;

		pde_2mb_64& free_pd_2mb_slot = memcpy_pd_2mb_table[pd_2mb_idx];
		free_pd_2mb_slot.present = true;
		free_pd_2mb_slot.write = true;
		free_pd_2mb_slot.large_page = true;


		// Pt
		uint32_t pt_idx = pt_helpers::find_free_pt_index(memcpy_pt_table);
		if (!pt_helpers::is_index_valid(pt_idx))
			return status_invalid_page_table_index;

		pte_64& pte_slot = memcpy_pt_table[pt_idx];
		pte_slot.present = true;
		pte_slot.write = true;

		return status_success;
	}

	project_status initialize_page_tables(void) {
		project_status status = allocate_page_tables();
		if (status != status_success)
			return status;

		status = copy_kernel_page_tables();
		if (status != status_success)
			return status;

		status = construct_my_page_tables();
		if (status != status_success)
			return status;

		return status;
	}

	// Initialization functions
	project_status init_physmem(void) {
		project_status status = initialize_page_tables();
		if (status != status_success)
			return status;

		return status_success;
	}
}