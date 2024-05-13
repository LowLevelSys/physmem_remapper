#include "physmem.hpp"

namespace physmem {
	/*
		Definitions
	*/
	constexpr int stress_test_count = 10'000;
	constexpr uint64_t KERNEL_CR3 = 0x1ad000;

	/*
		Global variables
	*/

	cr3 constructed_cr3 = { 0 };
	cr3 kernel_cr3 = { 0 };

	constructed_page_tables page_tables = { 0 };
	bool initialized = false;

	/*
		Initialization functions
	*/

	void* allocate_zero_table(PHYSICAL_ADDRESS max_addr) {
		void* table = (void*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

		if (table) 
			memset(table, 0, PAGE_SIZE);

		return table;
	}

	project_status allocate_page_tables(void) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		max_addr.QuadPart = MAXULONG64;

		page_tables.pml4_table = (pml4e_64*)allocate_zero_table(max_addr);
		if (!page_tables.pml4_table) 
			return status_memory_allocation_failed;

		for (uint64_t i = 0; i < TABLE_COUNT; i++) {
			page_tables.pdpt_table[i] = (pdpte_64*)allocate_zero_table(max_addr);
			page_tables.pd_table[i] = (pde_64*)allocate_zero_table(max_addr);
			page_tables.pt_table[i] = (pte_64*)allocate_zero_table(max_addr);

			if (!page_tables.pdpt_table[i] || !page_tables.pd_table[i] || !page_tables.pt_table[i])
				return status_memory_allocation_failed;
		}

		return status_success;
	}

	project_status copy_kernel_page_tables(void) {
		pml4e_64* kernel_pml4_page_table = 0;

		kernel_cr3.flags = KERNEL_CR3;
		kernel_pml4_page_table = (pml4e_64*)win_get_virtual_address(kernel_cr3.address_of_page_directory << 12);

		if (!kernel_pml4_page_table)
			return status_address_translation_failed;

		memcpy(page_tables.pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

		constructed_cr3.flags = kernel_cr3.flags;
		constructed_cr3.address_of_page_directory = win_get_physical_address(page_tables.pml4_table) >> 12;

		return status_success;
	}

	project_status construct_my_page_tables(void) {
		page_tables.memcpy_pml4e_idx = pt_helpers::find_free_pml4e_index(page_tables.pml4_table);

		if (!pt_helpers::is_index_valid(page_tables.memcpy_pml4e_idx))
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
		pml4e_64& free_pml4_slot = memcpy_pml4_table[page_tables.memcpy_pml4e_idx];
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

		// Safe the addresses of the tables used for memory copying
		page_tables.memcpy_pdpt_1gb_table = memcpy_pdpt_1gb_table;
		page_tables.memcpy_pd_2mb_table = memcpy_pd_2mb_table;
		page_tables.memcpy_pt_table = memcpy_pt_table;

		// Safe the indexes of the memcpy tables that are used
		page_tables.memcpy_pdpt_idx = pdpt_idx;
		page_tables.memcpy_pdpt_large_idx = pdpt_1gb_idx;
		page_tables.memcpy_pd_idx = pd_idx;
		page_tables.memcpy_pd_large_idx = pd_2mb_idx;
		page_tables.memcpy_pt_idx = pt_idx;

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

	project_status init_physmem(void) {
		project_status status = initialize_page_tables();
		if (status != status_success)
			return status;

		initialized = true;

		return status_success;
	}


	/*
		Util
	*/
	void log_remaining_pte_entries(pte_64* pte_table) {
		for (uint32_t i = 0; i < 512; i++) {
			project_log_info("%d present flag: %d", i, pte_table[i].present);
		}
	}

	/*
		Core functions
	*/

	project_status map_4kb_page(uint64_t physical_address, void*& generated_va) {
		if (!initialized)
			return status_not_initialized;

		if (!physical_address || !physical_address >> 12)
			return status_invalid_parameter;

		if (__readcr3() != constructed_cr3.flags) {
			project_log_error("Wrong ctx");
			return status_wrong_context;
		}

		uint32_t pt_idx = pt_helpers::find_free_pt_index(page_tables.memcpy_pt_table);
		if (!pt_helpers::is_index_valid(pt_idx))
			return status_invalid_page_table_index;

		pte_64& pte = page_tables.memcpy_pt_table[pt_idx];
		pte.flags = 0;

		pte.present = true;
		pte.write = true;
		pte.page_frame_number = physical_address >> 12;

		va_64 generated_address = { 0 };

		generated_address.pml4e_idx = page_tables.memcpy_pml4e_idx;
		generated_address.pdpte_idx = page_tables.memcpy_pdpt_idx;
		generated_address.pde_idx = page_tables.memcpy_pd_idx;
		generated_address.pte_idx = pt_idx;

		generated_va = (void*)generated_address.flags;

		__invlpg(generated_va);

		return status_success;
	}

	void unmap_4kb_page(void* mapped_page) {
		if (!initialized)
			return;

		if (__readcr3() != constructed_cr3.flags)
			return;

		va_64 va = { 0 };
		va.flags = (uint64_t)mapped_page;

		pte_64& pte = page_tables.memcpy_pt_table[va.pte_idx];
		pte.flags = 0;

		__invlpg(mapped_page);
	}

	void safely_unmap_4kb_page(void* mapped_page) {
		if (mapped_page)
			unmap_4kb_page(mapped_page);
	}

	project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address) {
		if (!initialized)
			return status_not_initialized;

		if (__readcr3() != constructed_cr3.flags) {
			project_log_error("Wrong ctx: %p", __readcr3());
			return status_wrong_context;
		}

		UNREFERENCED_PARAMETER(physical_address);
		cr3 target_cr3 = { 0 };
		va_64 va = { 0 };

		target_cr3.flags = outside_target_cr3;
		va.flags = (uint64_t)virtual_address;

		project_status status = status_success;
		pml4e_64* mapped_pml4_table = 0;
		/*
		pml4e_64* mapped_pml4_entry = 0;

		pdpte_64* mapped_pdpt_table = 0;
		pdpte_64* mapped_pdpt_entry = 0;

		pde_64* mapped_pde_table = 0;
		pde_64* mapped_pde_entry = 0;

		pte_64* mapped_pte_table = 0;
		pte_64* mapped_pte_entry = 0;
		*/
		status = map_4kb_page(target_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table);

		if (status != status_success)
			goto cleanup;
		/*
		mapped_pml4_entry = &mapped_pml4_table[va.pml4e_idx];

		mapped_pdpt_table = 0;
		status = map_4kb_page(mapped_pml4_entry->page_frame_number << 12, (void*&)mapped_pdpt_table);

		if (status != status_success)
			goto cleanup;

		mapped_pdpt_entry = &mapped_pdpt_table[va.pdpte_idx];

		if (mapped_pdpt_entry->large_page) {
			pdpte_1gb_64 mapped_pdpte_1gb_entry;
			mapped_pdpte_1gb_entry.flags = mapped_pdpt_entry->flags;

			physical_address = (mapped_pdpte_1gb_entry.page_frame_number << 30) + va.offset_1gb;
			goto cleanup;
		}

		mapped_pde_table = 0;
		status = map_4kb_page(mapped_pdpt_entry->page_frame_number << 12, (void*&)mapped_pde_table);

		if (status != status_success)
			goto cleanup;

		mapped_pde_entry = &mapped_pde_table[va.pde_idx];

		if (mapped_pde_entry->large_page) {
			pde_2mb_64 mapped_pde_2mb_entry;
			mapped_pde_2mb_entry.flags = mapped_pde_entry->flags;

			physical_address = (mapped_pde_2mb_entry.page_frame_number << 30) + va.offset_2mb;
			goto cleanup;
		}

		mapped_pte_table = 0;
		status = map_4kb_page(mapped_pde_entry->page_frame_number << 12, (void*&)mapped_pte_table);

		if (status != status_success)
			goto cleanup;

		mapped_pte_entry = &mapped_pte_table[va.pte_idx];
		physical_address = mapped_pte_entry->page_frame_number << 12;

		goto cleanup;
		*/
	cleanup:
		safely_unmap_4kb_page(mapped_pml4_table);
		//safely_unmap_4kb_page(mapped_pdpt_table);
		//safely_unmap_4kb_page(mapped_pde_table);
		//safely_unmap_4kb_page(mapped_pte_table);

		return status;
	}

	/*
		Exposed API's
	*/

	project_status copy_physical_memory(uint64_t destination_physical, uint64_t source_physical, uint64_t size) {
		if (!initialized)
			return status_not_initialized;

		project_status status = status_success;
		uint64_t copied_bytes = 0;
		uint64_t curr_cr3 = __readcr3();

		_mm_lfence();
		__writecr3(constructed_cr3.flags);
		_mm_lfence();

		while (copied_bytes < size) {
			void* current_virtual_mapped_source = 0;
			void* current_virtual_mapped_destination = 0;
			uint64_t copyable_size = 0;

			// Map the pa's

			status = map_4kb_page(source_physical + copied_bytes, current_virtual_mapped_source);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				break;
			}

			status = map_4kb_page(destination_physical + copied_bytes, current_virtual_mapped_destination);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				safely_unmap_4kb_page(current_virtual_mapped_destination);
				break;
			}

			copyable_size = min(PAGE_SIZE, size - copied_bytes);

			// Then copy the mem

			__invlpg(current_virtual_mapped_source);
			__invlpg(current_virtual_mapped_destination);
			_mm_lfence();

			memcpy(current_virtual_mapped_destination, current_virtual_mapped_source, copyable_size);

			copied_bytes += copyable_size;

			safely_unmap_4kb_page(current_virtual_mapped_source);
			safely_unmap_4kb_page(current_virtual_mapped_destination);
		}

		_mm_lfence();
		__writecr3(curr_cr3);
		_mm_lfence();

		return status;
	}

	project_status copy_virtual_memory(void* destination, void* source, uint64_t size, uint64_t destination_cr3, uint64_t source_cr3) {
		if (!initialized)
			return status_not_initialized;


		cr3 target_source_cr3 = { 0 };
		cr3 target_destination_cr3 = { 0 };

		target_source_cr3.flags = source_cr3;
		target_destination_cr3.flags = destination_cr3;

		project_status status = status_success;
		uint64_t copied_bytes = 0;
		uint64_t curr_cr3 = __readcr3();

		_mm_lfence();
		__writecr3(constructed_cr3.flags);
		_mm_lfence();

		while (copied_bytes < size) {
			//void* current_virtual_mapped_source = 0;
			//void* current_virtual_mapped_destination = 0;

			uint64_t current_physical_source = 0;
			uint64_t current_physical_destination = 0;

			uint64_t copyable_size = PAGE_SIZE;
			
			// First translate the va's to pa's 

			status = translate_to_physical_address(source_cr3, (void*)((uint64_t)source + copied_bytes), current_physical_source);
			if (status != status_success)
				break;

			status = translate_to_physical_address(source_cr3, (void*)((uint64_t)destination + copied_bytes), current_physical_destination);
			if (status != status_success)
				break;
			/*
			// Then map the pa's

			status = map_4kb_page(current_physical_source, current_virtual_mapped_source);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				break;
			}

			status = map_4kb_page(current_physical_destination, current_virtual_mapped_destination);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				safely_unmap_4kb_page(current_virtual_mapped_destination);
				break;
			}

			copyable_size = min(PAGE_SIZE, size - copied_bytes);

			// Then copy the mem

			__invlpg(current_virtual_mapped_source);
			__invlpg(current_virtual_mapped_destination);
			_mm_lfence();

			memcpy(current_virtual_mapped_destination, current_virtual_mapped_source, copyable_size);
			

			safely_unmap_4kb_page(current_virtual_mapped_source);
			safely_unmap_4kb_page(current_virtual_mapped_destination);
			*/
			copied_bytes += copyable_size;
		}

		_mm_lfence();
		__writecr3(curr_cr3);
		_mm_lfence();

		return status;
	}

	/*
		Exposed tests
	*/

	project_status stress_test_memory_copy(void) {
		uint64_t test_size = PAGE_SIZE * 10;
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;

		max_addr.QuadPart = MAXULONG64;

		void* pool = ExAllocatePool(NonPagedPool, test_size);
		void* contiguous_mem = MmAllocateContiguousMemory(test_size, max_addr);

		if (!pool || !contiguous_mem)
			return status_memory_allocation_failed;

		project_log_info("Stresstest environment cr3: %p", __readcr3());
		project_log_info("Constructed environment cr3: %p", constructed_cr3.flags);
		project_log_info("Kernel environment cr3: %p", kernel_cr3.flags);

		for (int i = 0; i < stress_test_count; i++) {
			memset(contiguous_mem, i, test_size);
			memcpy(pool, contiguous_mem, test_size);

			status = copy_virtual_memory(contiguous_mem, pool, test_size, __readcr3(), __readcr3());
			if (status != status_success)
				goto cleanup;

			if (memcmp(pool, contiguous_mem, test_size) != 0) {
				status = status_data_mismatch;
				goto cleanup;
			}
		}

		status = status_success;

	cleanup:
		if (pool) ExFreePool(pool);
		if (contiguous_mem) MmFreeContiguousMemory(contiguous_mem);

		if (status == status_success) {
			project_log_success("Stress test finished successfully");
		}

		return status;
	}
}