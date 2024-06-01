#include "physmem.hpp"

#include "../interrupts/interrupts.hpp"
#include "../project_utility.hpp"

namespace physmem {
	/*
		Definitions
	*/
	constexpr int stress_test_count = 10'000;

	/*
		Declarations
	*/
	void log_remaining_pte_entries(pte_64* pte_table);
	project_status get_pte_entry(void* virtual_address, uint64_t mem_cr3_u64, pte_64*& mem_pte);
	void safely_unmap_4kb_page(void* mapped_page);

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
			crt::memset(table, 0, PAGE_SIZE);

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

		kernel_cr3.flags = utility::get_cr3(4);
		if (!kernel_cr3.flags)
			return status_cr3_not_found;

		kernel_pml4_page_table = (pml4e_64*)win_get_virtual_address(kernel_cr3.address_of_page_directory << 12);

		if (!kernel_pml4_page_table)
			return status_address_translation_failed;

		crt::memcpy(page_tables.pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

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

		// Pd
		uint32_t pd_idx = pt_helpers::find_free_pd_index(memcpy_pd_table);
		if (!pt_helpers::is_index_valid(pd_idx))
			return status_invalid_page_table_index;

		pde_64& free_pd_slot = memcpy_pd_table[pdpt_idx];
		free_pd_slot.present = true;
		free_pd_slot.write = true;
		free_pd_slot.page_frame_number = pt_pfn;

		// Safe the addresses of the tables used for memory copying
		page_tables.memcpy_pdpt_1gb_table = memcpy_pdpt_1gb_table;
		page_tables.memcpy_pd_2mb_table = memcpy_pd_2mb_table;
		page_tables.memcpy_pt_table = memcpy_pt_table;

		// Safe the indexes of the memcpy tables that are used
		page_tables.memcpy_pdpt_idx = pdpt_idx;
		page_tables.memcpy_pd_idx = pd_idx;

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

	project_status get_remapping_entry(void* mem, remapped_entry_t*& remapping_entry) {
		project_status status = status_remapping_entry_found;
		va_64 target_va = { 0 };
		remapped_entry_t dummy = { 0 };
		remapped_entry_t* curr_closest_entry = &dummy;

		target_va.flags = (uint64_t)mem;

		for (uint32_t i = 0; i < REMAPPING_COUNT; i++) {
			remapped_entry_t* curr_entry = &page_tables.remapping_list[i];

			// Sort out all the irrelevant ones
			if (!curr_entry->used)
				continue;

			// Check whether the pml4 index overlaps
			if (curr_entry->remapped_va.pml4e_idx != target_va.pml4e_idx)
				continue;

			// Check whether the pdpt index overlaps
			if (curr_entry->remapped_va.pdpte_idx != target_va.pdpte_idx) {

				// The curr closest entry is already as good as the entry at the current index
				if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx)
					continue;

				// Set the curr entry as closest entry
				curr_closest_entry = curr_entry;
				continue;
			}

			// If it points to an entry marked as large page
			// we can return it immediately as there won't be
			// a more fitting entry than this one (paging hierachy
			// for that va range ends there
			if (curr_entry->pdpt_table.large_page) {
				curr_closest_entry = curr_entry;
				goto cleanup;
			}

			// Check whether the pde index overlaps
			if (curr_entry->remapped_va.pde_idx != target_va.pde_idx) {

				// The curr closest entry is already as good as the entry at the current index
				if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx &&
					curr_closest_entry->remapped_va.pdpte_idx == target_va.pdpte_idx)
					continue;

				// Set the curr entry as closest entry
				curr_closest_entry = curr_entry;
				continue;
			}

			if (curr_entry->pd_table.large_page) {
				curr_closest_entry = curr_entry;
				goto cleanup;
			}

			// Check whether the pte index overlaps
			if (curr_entry->remapped_va.pte_idx != target_va.pte_idx) {

				// The curr closest entry is already as good as the entry at the current index
				if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx &&
					curr_closest_entry->remapped_va.pdpte_idx == target_va.pdpte_idx &&
					curr_closest_entry->remapped_va.pde_idx == target_va.pde_idx)
					continue;

				// Set the curr entry as closest entry
				curr_closest_entry = curr_entry;
				continue;
			}

			// Everything overlapped, the address resides in the same pte table
			// as another one we mapped, we can reuse everything
			curr_closest_entry = curr_entry;
			goto cleanup;
		}

	cleanup:

		if (curr_closest_entry == &dummy) {
			status = status_no_valid_remapping_entry;
		}
		else {
			remapping_entry = curr_closest_entry;
		}

		return status;
	}

	project_status add_remapping_entry(remapped_entry_t new_entry) {
		project_status status = status_success;

		for (uint32_t i = 0; i < REMAPPING_COUNT; i++) {
			remapped_entry_t* curr_entry = &page_tables.remapping_list[i];

			// Check whether the current entry is present/occupied
			if (curr_entry->used)
				continue;
			crt::memcpy(curr_entry, &new_entry, sizeof(remapped_entry_t));
			curr_entry->used = true;

			break;
		}

		status = status_remapping_list_full;
		return status;
	}

	project_status remove_remapping_entry(remapped_entry_t* remapping_entry) {
		if (!remapping_entry)
			return status_invalid_parameter;

		project_status status = status_success;

		for (uint32_t i = 0; i < REMAPPING_COUNT; i++) {
			remapped_entry_t* curr_entry = &page_tables.remapping_list[i];

			if (curr_entry != remapping_entry)
				continue;

			crt::memset(curr_entry, 0, sizeof(remapped_entry_t));

			status = status_success;
			return status;
		}

		status = status_remapping_entry_not_found;
		return status;

	}

	project_status get_max_remapping_level(remapped_entry_t* remapping_entry, uint64_t target_address, usable_until& usable_level) {
		va_64 target_va = { 0 };
		target_va.flags = target_address;

		if (!remapping_entry || !target_address) {
			usable_level = non_valid;
			return status_invalid_parameter;
		}

		// Check whether the pml4 index overlaps
		if (remapping_entry->remapped_va.pml4e_idx != target_va.pml4e_idx) {
			usable_level = non_valid;
			return status_invalid_parameter;
		}

		// Check whether the pdpt index overlaps
		if (remapping_entry->remapped_va.pdpte_idx != target_va.pdpte_idx) {
			usable_level = pdpt_table_valid;
			return status_success;
		}

		if (remapping_entry->pdpt_table.large_page) {
			usable_level = pdpt_table_valid;
			return status_success;
		}

		// Check whether the pde index overlaps
		if (remapping_entry->remapped_va.pde_idx != target_va.pde_idx) {
			usable_level = pde_table_valid;
			return status_success;
		}

		if (remapping_entry->pd_table.large_page) {
			usable_level = pde_table_valid;
			return status_success;
		}

		usable_level = pte_table_valid;
		return status_success;
	}

	void safely_set_reusable_level(restorable_until& old_level, restorable_until new_level) {
		if (new_level > old_level) {
			new_level = old_level;
		}
	}

	project_status get_max_restorable_level(remapped_entry_t* remapping_entry, restorable_until& restorable_level) {
		restorable_level = pdpt_table_removeable;

		for (uint32_t i = 0; i < REMAPPING_COUNT; i++) {
			remapped_entry_t* curr_entry = &page_tables.remapping_list[i];

			// Check whether it is a valid entry to compare against
			if (!curr_entry->used || curr_entry == remapping_entry)
				continue;

			// Check whether pt tables overlap
			if (curr_entry->pt_table == remapping_entry->pt_table) {
				safely_set_reusable_level(restorable_level, nothing_removeable);
			}

			// Check whether pd tables overlap
			if (curr_entry->pd_table.table == remapping_entry->pd_table.table) {
				safely_set_reusable_level(restorable_level, pte_table_removeable);
			}

			// Check whether pdpt tables overlap
			if (curr_entry->pdpt_table.table == remapping_entry->pdpt_table.table) {
				safely_set_reusable_level(restorable_level, pde_table_removeable);
			}

		}

		return status_success;
	}

	/*
		Core functions
	*/

	project_status map_4kb_page(uint64_t physical_address, void*& generated_va, uint64_t* remaining_mapped_bytes) {
		if (!initialized)
			return status_not_initialized;

		if (!physical_address || !(physical_address >> 12))
			return status_invalid_parameter;

		if (__readcr3() != constructed_cr3.flags) {
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

		// Then we always page align the physical address to the nearest 4kb boundary and calculate a page offset
		uint64_t aligned_page = (physical_address >> 12) << 12;
		uint64_t offset = physical_address - aligned_page;
		generated_address.offset_4kb = offset;

		// Tell the user how many bytes he has remaining
		if (remaining_mapped_bytes)
			*remaining_mapped_bytes = 0x1000 - generated_address.offset_4kb;

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

	project_status get_pte_entry(void* virtual_address, uint64_t mem_cr3_u64, pte_64*& mem_pte) {
		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		cr3 target_cr3 = { 0 };
		va_64 va = { 0 };

		target_cr3.flags = mem_cr3_u64;
		va.flags = (uint64_t)virtual_address;

		project_status status = status_success;
		pml4e_64* mapped_pml4_table = 0;

		pml4e_64* mapped_pml4_entry = 0;

		pdpte_64* mapped_pdpt_table = 0;
		pdpte_64* mapped_pdpt_entry = 0;

		pde_64* mapped_pde_table = 0;
		pde_64* mapped_pde_entry = 0;

		pte_64* mapped_pte_table = 0;
		pte_64* mapped_pte_entry = 0;

		status = map_4kb_page(target_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pml4_entry = &mapped_pml4_table[va.pml4e_idx];

		status = map_4kb_page(mapped_pml4_entry->page_frame_number << 12, (void*&)mapped_pdpt_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pdpt_entry = &mapped_pdpt_table[va.pdpte_idx];

		if (mapped_pdpt_entry->large_page) {
			status = status_paging_wrong_granularity;
			goto cleanup;
		}

		status = map_4kb_page(mapped_pdpt_entry->page_frame_number << 12, (void*&)mapped_pde_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pde_entry = &mapped_pde_table[va.pde_idx];

		if (mapped_pde_entry->large_page) {
			status = status_paging_wrong_granularity;
			goto cleanup;
		}

		status = map_4kb_page(mapped_pde_entry->page_frame_number << 12, (void*&)mapped_pte_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pte_entry = &mapped_pte_table[va.pte_idx];

		mem_pte = mapped_pte_entry;

		goto cleanup;

	cleanup:
		safely_unmap_4kb_page(mapped_pml4_table);
		safely_unmap_4kb_page(mapped_pdpt_table);
		safely_unmap_4kb_page(mapped_pde_table);

		// safely_unmap_4kb_page(mapped_pte_table);

		return status;
	}

	project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address) {
		if (!initialized)
			return status_not_initialized;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		cr3 target_cr3 = { 0 };
		va_64 va = { 0 };

		target_cr3.flags = outside_target_cr3;
		va.flags = (uint64_t)virtual_address;

		project_status status = status_success;
		pml4e_64* mapped_pml4_table = 0;

		pml4e_64* mapped_pml4_entry = 0;

		pdpte_64* mapped_pdpt_table = 0;
		pdpte_64* mapped_pdpt_entry = 0;

		pde_64* mapped_pde_table = 0;
		pde_64* mapped_pde_entry = 0;

		pte_64* mapped_pte_table = 0;
		pte_64* mapped_pte_entry = 0;

		status = map_4kb_page(target_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pml4_entry = &mapped_pml4_table[va.pml4e_idx];
		if (!mapped_pml4_entry->present) {
			status = status_not_present;
			goto cleanup;
		}

		status = map_4kb_page(mapped_pml4_entry->page_frame_number << 12, (void*&)mapped_pdpt_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pdpt_entry = &mapped_pdpt_table[va.pdpte_idx];
		if (!mapped_pdpt_entry->present) {
			status = status_not_present;
			goto cleanup;
		}

		if (mapped_pdpt_entry->large_page) {
			pdpte_1gb_64 mapped_pdpte_1gb_entry;
			mapped_pdpte_1gb_entry.flags = mapped_pdpt_entry->flags;

			physical_address = (mapped_pdpte_1gb_entry.page_frame_number << 30) + va.offset_1gb;
			if (!physical_address) {
				status = status_invalid_return_value;
			}

			goto cleanup;
		}

		status = map_4kb_page(mapped_pdpt_entry->page_frame_number << 12, (void*&)mapped_pde_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pde_entry = &mapped_pde_table[va.pde_idx];
		if (!mapped_pde_entry->present) {
			status = status_not_present;
			goto cleanup;
		}

		if (mapped_pde_entry->large_page) {
			pde_2mb_64 mapped_pde_2mb_entry;
			mapped_pde_2mb_entry.flags = mapped_pde_entry->flags;

			physical_address = (mapped_pde_2mb_entry.page_frame_number << 21) + va.offset_2mb;
			if (!physical_address) {
				status = status_invalid_return_value;
			}

			goto cleanup;
		}

		status = map_4kb_page(mapped_pde_entry->page_frame_number << 12, (void*&)mapped_pte_table, 0);

		if (status != status_success)
			goto cleanup;

		mapped_pte_entry = &mapped_pte_table[va.pte_idx];
		if (!mapped_pte_entry->present) {
			status = status_not_present;
			goto cleanup;
		}

		physical_address = (mapped_pte_entry->page_frame_number << 12) + va.offset_4kb;
		if (!physical_address) {
			status = status_invalid_return_value;
		}

		goto cleanup;

	cleanup:
		safely_unmap_4kb_page(mapped_pml4_table);
		safely_unmap_4kb_page(mapped_pdpt_table);
		safely_unmap_4kb_page(mapped_pde_table);
		safely_unmap_4kb_page(mapped_pte_table);

		return status;
	}

	project_status ensure_memory_mapping_without_previous_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size) {
		if (!initialized)
			return status_not_initialized;

		if (!ensured_size ||!mem ||!mem_cr3_u64)
			return status_invalid_parameter;

		if (__readcr3() != constructed_cr3.flags) {
			return status_wrong_context;
		}

		va_64 mem_va = { 0 };
		cr3 mem_cr3 = { 0 };

		mem_va.flags = (uint64_t)mem;
		mem_cr3.flags = mem_cr3_u64;
		project_status status = status_success;

		// Pointers to mapped system tables
		pml4e_64* mapped_pml4_table = 0;
		pdpte_64* mapped_pdpt_table = 0;
		pde_64* mapped_pde_table = 0;
		pte_64* mapped_pte_table = 0;

		// Pointers to my tables
		pml4e_64* my_pml4_table = 0;
		pdpte_64* my_pdpt_table = 0;
		pde_64* my_pde_table = 0;
		pte_64* my_pte_table = 0;

		// Physical addresses of my page tables
		uint64_t pdpt_phys = 0;
		uint64_t pd_phys = 0;
		uint64_t pt_phys = 0;

		// A new entry for remapping
		remapped_entry_t new_entry = { 0 };

		my_pml4_table = page_tables.pml4_table;

		status = map_4kb_page(mem_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table, 0);
		if (status != status_success)
			goto cleanup;

		status = map_4kb_page(mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12, (void*&)mapped_pdpt_table, 0);
		if (status != status_success)
			goto cleanup;

		if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
			my_pdpt_table = pt_manager::get_free_pdpt_table(&page_tables);
			if (!my_pdpt_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			pdpte_1gb_64* my_1gb_pdpt_table = (pdpte_1gb_64*)my_pdpt_table;

			if (translate_to_physical_address(kernel_cr3.flags, my_1gb_pdpt_table, pdpt_phys) != status_success)
				goto cleanup;

			crt::memcpy(my_1gb_pdpt_table, mapped_pdpt_table, sizeof(pdpte_1gb_64) * 512);
			crt::memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

			my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

			// Create a new remapping entry
			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = true;
			new_entry.pdpt_table.table = my_pdpt_table;

			add_remapping_entry(new_entry);

			*ensured_size = 0x40000000 - mem_va.offset_1gb;

			goto cleanup;
		}

		status = map_4kb_page(mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12, (void*&)mapped_pde_table, 0);
		if (status != status_success)
			goto cleanup;

		if (mapped_pde_table[mem_va.pde_idx].large_page) {
			my_pdpt_table = pt_manager::get_free_pdpt_table(&page_tables);
			if (!my_pdpt_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			my_pde_table = pt_manager::get_free_pd_table(&page_tables);
			if (!my_pde_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			pde_2mb_64* my_2mb_pd_table = (pde_2mb_64*)my_pde_table;

			if (translate_to_physical_address(kernel_cr3.flags, my_pdpt_table, pdpt_phys) != status_success)
				goto cleanup;

			if (translate_to_physical_address(kernel_cr3.flags, my_pde_table, pd_phys) != status_success)
				goto cleanup;


			crt::memcpy(my_2mb_pd_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
			crt::memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
			crt::memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

			my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;
			my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

			// Create a new remapping entry
			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = my_pdpt_table;

			new_entry.pd_table.large_page = true;
			new_entry.pd_table.table = my_pde_table;

			add_remapping_entry(new_entry);

			*ensured_size = 0x200000 - mem_va.offset_2mb;

			goto cleanup;
		}

		status = map_4kb_page(mapped_pde_table[mem_va.pde_idx].page_frame_number << 12, (void*&)mapped_pte_table, 0);
		if (status != status_success)
			goto cleanup;

		my_pdpt_table = pt_manager::get_free_pdpt_table(&page_tables);
		if (!my_pdpt_table) {
			status = status_invalid_my_page_table;
			goto cleanup;
		}

		my_pde_table = pt_manager::get_free_pd_table(&page_tables);
		if (!my_pde_table) {
			status = status_invalid_my_page_table;
			goto cleanup;
		}

		my_pte_table = pt_manager::get_free_pt_table(&page_tables);
		if (!my_pte_table) {
			status = status_invalid_my_page_table;
			goto cleanup;
		}

		status = translate_to_physical_address(kernel_cr3.flags, my_pdpt_table, pdpt_phys);
		if (status != status_success)
			goto cleanup;

		status = translate_to_physical_address(kernel_cr3.flags, my_pde_table, pd_phys);
		if (status != status_success)
			goto cleanup;

		status = translate_to_physical_address(kernel_cr3.flags, my_pte_table, pt_phys);
		if (status != status_success)
			goto cleanup;

		crt::memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
		crt::memcpy(my_pde_table, mapped_pde_table, sizeof(pde_64) * 512);
		crt::memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
		crt::memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

		my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;
		my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;
		my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;

		// Create a new remapping entry
		new_entry.used = true;
		new_entry.remapped_va = mem_va;

		new_entry.pdpt_table.large_page = false;
		new_entry.pdpt_table.table = my_pdpt_table;

		new_entry.pd_table.large_page = false;
		new_entry.pd_table.table = my_pde_table;

		new_entry.pt_table = my_pte_table;

		add_remapping_entry(new_entry);

		*ensured_size = 0x1000 - mem_va.offset_4kb;

	cleanup:

		safely_unmap_4kb_page(mapped_pml4_table);
		safely_unmap_4kb_page(mapped_pdpt_table);
		safely_unmap_4kb_page(mapped_pde_table);
		safely_unmap_4kb_page(mapped_pte_table);

		if (status != status_success) {
			pt_manager::safely_free_pdpt_table(&page_tables, my_pdpt_table);
			pt_manager::safely_free_pd_table(&page_tables, my_pde_table);
			pt_manager::safely_free_pt_table(&page_tables, my_pte_table);

			return status;
		}
		else {
			__invlpg(mem);
		}

		return status;
	}

	project_status ensure_memory_mapping_with_previous_mapping(void* mem, uint64_t mem_cr3_u64, remapped_entry_t* remapping_entry, uint64_t* ensured_size) {
		if (!initialized)
			return status_not_initialized;

		if (!ensured_size)
			return status_invalid_parameter;

		if (__readcr3() != constructed_cr3.flags) {
			return status_wrong_context;
		}

		va_64 mem_va = { 0 };
		cr3 mem_cr3 = { 0 };

		mem_va.flags = (uint64_t)mem;
		mem_cr3.flags = mem_cr3_u64;
		project_status status = status_success;

		// Pointers to mapped system tables
		pml4e_64* mapped_pml4_table = 0;
		pdpte_64* mapped_pdpt_table = 0;
		pde_64* mapped_pde_table = 0;
		pte_64* mapped_pte_table = 0;

		// Pointers to my tables
		pml4e_64* my_pml4_table = 0;
		pdpte_64* my_pdpt_table = 0;
		pde_64* my_pde_table = 0;
		pte_64* my_pte_table = 0;

		// Physical addresses of my page tables
		uint64_t pd_phys = 0;
		uint64_t pt_phys = 0;

		// A new entry for remapping
		remapped_entry_t new_entry = { 0 };

		usable_until max_usable = non_valid;
		status = get_max_remapping_level(remapping_entry, (uint64_t)mem, max_usable);
		if (status != status_success)
			goto cleanup;

		my_pml4_table = page_tables.pml4_table;

		status = map_4kb_page(mem_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table, 0);
		if (status != status_success)
			goto cleanup;

		status = map_4kb_page(mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12, (void*&)mapped_pdpt_table, 0);
		if (status != status_success)
			goto cleanup;

		if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
			switch (max_usable) {
			case pdpt_table_valid:
			case pde_table_valid:
			case pte_table_valid: {
				my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
				if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
					status = status_address_already_remapped;
					goto cleanup;
				}

				my_pdpt_table[mem_va.pdpte_idx].flags = mapped_pdpt_table[mem_va.pdpte_idx].flags;

				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = true;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				add_remapping_entry(new_entry);

				*ensured_size = 0x40000000 - mem_va.offset_1gb;

				goto cleanup;
			}
			case non_valid: {
				status = status_non_valid_usable_until_level;
				goto cleanup;
			}
			}
		}

		status = map_4kb_page(mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12, (void*&)mapped_pde_table, 0);
		if (status != status_success)
			goto cleanup;

		if (mapped_pde_table[mem_va.pde_idx].large_page) {
			switch (max_usable) {
			case pdpt_table_valid: {
				my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
				if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
					status = status_address_already_remapped;
					goto cleanup;
				}

				my_pde_table = pt_manager::get_free_pd_table(&page_tables);
				if (!my_pde_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}

				status = translate_to_physical_address(kernel_cr3.flags, my_pde_table, pd_phys);
				if (status != status_success)
					goto cleanup;

				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

				crt::memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);

				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = true;
				new_entry.pd_table.table = my_pde_table;

				add_remapping_entry(new_entry);

				*ensured_size = 0x200000 - mem_va.offset_2mb;

				goto cleanup;
			}
			case pde_table_valid:
			case pte_table_valid: {
				pde_2mb_64* my_2mb_pde_table = (pde_2mb_64*)remapping_entry->pd_table.table;
				if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
					status = status_address_already_remapped;
					goto cleanup;
				}

				my_2mb_pde_table[mem_va.pde_idx].flags = mapped_pde_table[mem_va.pde_idx].flags;

				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = true;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				add_remapping_entry(new_entry);

				*ensured_size = 0x200000 - mem_va.offset_2mb;

				goto cleanup;
			}
			case non_valid: {
				status = status_non_valid_usable_until_level;
				goto cleanup;
			}
			}
		}

		status = map_4kb_page(mapped_pde_table[mem_va.pde_idx].page_frame_number << 12, (void*&)mapped_pte_table, 0);
		if (status != status_success)
			goto cleanup;

		switch (max_usable) {
		case pdpt_table_valid: {
			my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
			if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
				status = status_address_already_remapped;
				goto cleanup;
			}

			my_pde_table = pt_manager::get_free_pd_table(&page_tables);
			if (!my_pde_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			status = translate_to_physical_address(kernel_cr3.flags, my_pde_table, pd_phys);
			if (status != status_success)
				goto cleanup;

			my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

			crt::memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);

			my_pte_table = pt_manager::get_free_pt_table(&page_tables);
			if (!my_pte_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			status = translate_to_physical_address(kernel_cr3.flags, my_pte_table, pt_phys);
			if (status != status_success)
				goto cleanup;

			my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;

			crt::memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);

			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

			new_entry.pd_table.large_page = false;
			new_entry.pd_table.table = my_pde_table;

			new_entry.pt_table = my_pte_table;

			add_remapping_entry(new_entry);

			*ensured_size = 0x1000 - mem_va.offset_4kb;

			goto cleanup;
		}
		case pde_table_valid: {
			my_pde_table = (pde_64*)remapping_entry->pd_table.table;
			if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
				status = status_address_already_remapped;
				goto cleanup;
			}

			my_pte_table = pt_manager::get_free_pt_table(&page_tables);
			if (!my_pte_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			status = translate_to_physical_address(kernel_cr3.flags, my_pte_table, pt_phys);
			if (status != status_success)
				goto cleanup;

			my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;

			crt::memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);

			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

			new_entry.pd_table.large_page = false;
			new_entry.pd_table.table = remapping_entry->pd_table.table;

			new_entry.pt_table = my_pte_table;

			add_remapping_entry(new_entry);

			*ensured_size = 0x1000 - mem_va.offset_4kb;

			goto cleanup;
		}
		case pte_table_valid: {
			my_pte_table = (pte_64*)remapping_entry->pt_table;
			if (mem_va.pte_idx == remapping_entry->remapped_va.pte_idx) {
				status = status_address_already_remapped;
				goto cleanup;
			}

			my_pte_table[mem_va.pte_idx].flags = mapped_pte_table[mem_va.pte_idx].flags;

			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

			new_entry.pd_table.large_page = false;
			new_entry.pd_table.table = remapping_entry->pd_table.table;

			new_entry.pt_table = remapping_entry->pt_table;

			add_remapping_entry(new_entry);

			*ensured_size = 0x1000 - mem_va.offset_4kb;

			goto cleanup;
		}
		case non_valid: {
			status = status_non_valid_usable_until_level;
			goto cleanup;
		}
		}

	cleanup:

		safely_unmap_4kb_page(mapped_pml4_table);
		safely_unmap_4kb_page(mapped_pdpt_table);
		safely_unmap_4kb_page(mapped_pde_table);
		safely_unmap_4kb_page(mapped_pte_table);

		if (status != status_success) {
			pt_manager::safely_free_pdpt_table(&page_tables, my_pdpt_table);
			pt_manager::safely_free_pd_table(&page_tables, my_pde_table);
			pt_manager::safely_free_pt_table(&page_tables, my_pte_table);

			return status;
		}
		else {
			__invlpg(mem);
		}

		return status;
	}

	project_status ensure_memory_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size = 0) {
		if (!initialized)
			return status_not_initialized;

		project_status status = status_success;
		remapped_entry_t* remapping_entry = 0;
		uint64_t dummy_size = 0;

		status = get_remapping_entry(mem, remapping_entry);

		if (!ensured_size)
			ensured_size = &dummy_size;

		if (status == status_remapping_entry_found) {
			status = ensure_memory_mapping_with_previous_mapping(mem, mem_cr3_u64, remapping_entry, ensured_size);
		}
		else {
			status = ensure_memory_mapping_without_previous_mapping(mem, mem_cr3_u64, ensured_size);
		}

		return status;
	}

	project_status unset_global_flag(void* target_address, uint64_t mem_cr3_u64, uint64_t* ensured_size) {
		if (!initialized)
			return status_not_initialized;

		if (!target_address || !mem_cr3_u64 || !ensured_size)
			return status_invalid_parameter;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;
		

		va_64 mem_va = { 0 };
		cr3 mem_cr3 = { 0 };

		mem_va.flags = (uint64_t)target_address;
		mem_cr3.flags = mem_cr3_u64;

		project_status status = status_success;

		// Pointers to mapped system tables
		pml4e_64* mapped_pml4_table = 0;
		pdpte_64* mapped_pdpt_table = 0;
		pde_64* mapped_pde_table = 0;
		pte_64* mapped_pte_table = 0;

		status = map_4kb_page(mem_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table, 0);
		if (status != status_success)
			goto cleanup;

		status = map_4kb_page(mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12, (void*&)mapped_pdpt_table, 0);
		if (status != status_success)
			goto cleanup;

		if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
			pdpte_1gb_64* pdpt_1gb_entry = (pdpte_1gb_64*)&mapped_pdpt_table[mem_va.pdpte_idx];

			pdpt_1gb_entry->global = false;

			*ensured_size = 0x40000000 - mem_va.offset_1gb;

			goto cleanup;
		}

		status = map_4kb_page(mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12, (void*&)mapped_pde_table, 0);
		if (status != status_success)
			goto cleanup;

		if (mapped_pde_table[mem_va.pde_idx].large_page) {
			pde_2mb_64* pd_2mb_entry = (pde_2mb_64*)&mapped_pde_table[mem_va.pde_idx];

			pd_2mb_entry->large_page = false;

			*ensured_size = 0x200000 - mem_va.offset_2mb;

			goto cleanup;
		}

		status = map_4kb_page(mapped_pde_table[mem_va.pde_idx].page_frame_number << 12, (void*&)mapped_pte_table, 0);
		if (status != status_success)
			goto cleanup;

		mapped_pte_table[mem_va.pte_idx].global = false;

		*ensured_size = 0x1000 - mem_va.offset_4kb;

	cleanup:

		safely_unmap_4kb_page(mapped_pml4_table);
		safely_unmap_4kb_page(mapped_pdpt_table);
		safely_unmap_4kb_page(mapped_pde_table);
		safely_unmap_4kb_page(mapped_pte_table);

		if (status == status_success) {
			__invlpg(target_address);
		}

		return status;
	}

	/*
		Exposed API's
	*/

	bool is_initialized(void) {
		return initialized;
	}

	cr3 get_constructed_cr3(void) {
		return constructed_cr3;
	}

	cr3 get_system_cr3(void) {
		return kernel_cr3;
	}

	project_status copy_physical_memory(uint64_t destination_physical, uint64_t source_physical, uint64_t size) {
		if (!initialized)
			return status_not_initialized;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		project_status status = status_success;
		uint64_t copied_bytes = 0;

		while (copied_bytes < size) {
			void* current_virtual_mapped_source = 0;
			void* current_virtual_mapped_destination = 0;

			uint64_t src_remaining = 0;
			uint64_t dst_remaining = 0;

			uint64_t copyable_size = 0;

			// Map the pa's

			status = map_4kb_page(source_physical + copied_bytes, current_virtual_mapped_source, &src_remaining);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				break;
			}

			status = map_4kb_page(destination_physical + copied_bytes, current_virtual_mapped_destination, &dst_remaining);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				safely_unmap_4kb_page(current_virtual_mapped_destination);
				break;
			}

			copyable_size = min(PAGE_SIZE, size - copied_bytes);
			copyable_size = min(copyable_size, src_remaining);
			copyable_size = min(copyable_size, dst_remaining);

			// Then copy the mem
			_mm_lfence();
			crt::memcpy(current_virtual_mapped_destination, current_virtual_mapped_source, copyable_size);
			_mm_lfence();

			safely_unmap_4kb_page(current_virtual_mapped_source);
			safely_unmap_4kb_page(current_virtual_mapped_destination);

			copied_bytes += copyable_size;
		}

		return status;
	}

	project_status copy_virtual_memory(void* destination, void* source, uint64_t size, uint64_t destination_cr3, uint64_t source_cr3) {
		if (!initialized)
			return status_not_initialized;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		project_status status = status_success;
		uint64_t copied_bytes = 0;

		while (copied_bytes < size) {
			void* current_virtual_mapped_source = 0;
			void* current_virtual_mapped_destination = 0;

			uint64_t current_physical_source = 0;
			uint64_t current_physical_destination = 0;

			uint64_t src_remaining = 0;
			uint64_t dst_remaining = 0;

			uint64_t copyable_size = 0;

			// First translate the va's to pa's 
			status = translate_to_physical_address(source_cr3, (void*)((uint64_t)source + copied_bytes), current_physical_source);
			if (status != status_success)
				break;

			status = translate_to_physical_address(destination_cr3, (void*)((uint64_t)destination + copied_bytes), current_physical_destination);
			if (status != status_success)
				break;
			
			// Then map the pa's
			status = map_4kb_page(current_physical_source, current_virtual_mapped_source, &src_remaining);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				break;
			}

			status = map_4kb_page(current_physical_destination, current_virtual_mapped_destination, &dst_remaining);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_source);
				safely_unmap_4kb_page(current_virtual_mapped_destination);
				break;
			}

			copyable_size = min(PAGE_SIZE, size - copied_bytes);
			copyable_size = min(copyable_size, src_remaining);
			copyable_size = min(copyable_size, dst_remaining);

			// Then copy the mem
			_mm_lfence();
			crt::memcpy(current_virtual_mapped_destination, current_virtual_mapped_source, copyable_size);
			_mm_lfence();

			safely_unmap_4kb_page(current_virtual_mapped_source);
			safely_unmap_4kb_page(current_virtual_mapped_destination);

			copied_bytes += copyable_size;
		}
		return status;
	}

	project_status copy_memory_to_constructed_cr3(void* destination, void* source, uint64_t size, uint64_t source_cr3) {
		if (!initialized)
			return status_not_initialized;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		project_status status = status_success;
		uint64_t copied_bytes = 0;

		while (copied_bytes < size) {
			void* current_src = 0;
			void* current_dst = (void*)((uint64_t)destination + copied_bytes);
			uint64_t current_physical_source = 0;
			uint64_t src_remaining = 0;

			// Translate the virtual address to physical address
			status = translate_to_physical_address(source_cr3, (void*)((uint64_t)source + copied_bytes), current_physical_source);
			if (status != status_success) {
				break;
			}

			// Map the physical address to a virtual address
			status = map_4kb_page(current_physical_source, current_src, &src_remaining);
			if (status != status_success) {
				safely_unmap_4kb_page(current_src);
				break;
			}

			uint64_t copyable_size = PAGE_SIZE;
			copyable_size = min(PAGE_SIZE, size - copied_bytes);
			copyable_size = min(copyable_size, src_remaining);

			// Copy the memory
			_mm_lfence();
			crt::memcpy(current_dst, current_src, copyable_size);
			_mm_lfence();

			safely_unmap_4kb_page(current_src);

			copied_bytes += copyable_size;
		}

		return status;
	}

	project_status copy_memory_from_constructed_cr3(void* destination, void* source, uint64_t size, uint64_t destination_cr3) {
		if (!initialized)
			return status_not_initialized;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		project_status status = status_success;
		uint64_t copied_bytes = 0;

		while (copied_bytes < size) {
			void* current_virtual_mapped_destination = 0;
			uint64_t current_physical_destination = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;

			// First translate the va's to pa's 

			status = translate_to_physical_address(destination_cr3, (void*)((uint64_t)destination + copied_bytes), current_physical_destination);
			if (status != status_success)
				break;

			// Then map the pa's

			status = map_4kb_page(current_physical_destination, current_virtual_mapped_destination, &dst_remaining);
			if (status != status_success) {
				safely_unmap_4kb_page(current_virtual_mapped_destination);
				break;
			}

			copyable_size = min(PAGE_SIZE, size - copied_bytes);
			copyable_size = min(copyable_size, dst_remaining);

			// Then copy the mem
			_mm_lfence();
			crt::memcpy(current_virtual_mapped_destination, (void*)((uint64_t)source + copied_bytes), copyable_size);
			_mm_lfence();

			safely_unmap_4kb_page(current_virtual_mapped_destination);

			copied_bytes += copyable_size;
		}

		return status;
	}

	project_status overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64) {
		if (PAGE_ALIGN(target_address) != target_address ||
			PAGE_ALIGN(new_memory) != new_memory)
			return status_non_aligned;

		if (__readcr3() != constructed_cr3.flags)
			return status_wrong_context;

		project_status status = status_success;

		cr3 new_mem_cr3 = { 0 };

		va_64 target_va = { 0 };
		va_64 new_mem_va = { 0 };

		target_va.flags = (uint64_t)target_address;
		new_mem_va.flags = (uint64_t)new_memory;

		new_mem_cr3.flags = (uint64_t)new_mem_cr3_u64;

		pml4e_64* my_pml4_table = 0;
		pdpte_64* my_pdpt_table = 0;
		pde_64* my_pde_table = 0;
		pte_64* my_pte_table = 0;

		pml4e_64* new_mem_pml4_table = 0;
		pdpte_64* new_mem_pdpt_table = 0;
		pde_64* new_mem_pde_table = 0;
		pte_64* new_mem_pte_table = 0;


		// First ensure the mapping of the my address
		// in our cr3
		status = ensure_memory_mapping(target_address, target_address_cr3_u64);
		if (status != status_success)
			goto cleanup;


		status = map_4kb_page(constructed_cr3.address_of_page_directory << 12, (void*&)my_pml4_table, 0);
		if (status != status_success)
			goto cleanup;
		status = map_4kb_page(new_mem_cr3.address_of_page_directory << 12, (void*&)new_mem_pml4_table, 0);
		if (status != status_success)
			goto cleanup;


		status = map_4kb_page(my_pml4_table[target_va.pml4e_idx].page_frame_number << 12, (void*&)my_pdpt_table, 0);
		if (status != status_success)
			goto cleanup;
		status = map_4kb_page(new_mem_pml4_table[new_mem_va.pml4e_idx].page_frame_number << 12, (void*&)new_mem_pdpt_table, 0);
		if (status != status_success)
			goto cleanup;


		if (my_pdpt_table[target_va.pdpte_idx].large_page || new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
			if (!my_pdpt_table[target_va.pdpte_idx].large_page || !new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
				status = status_paging_wrong_granularity;
				goto cleanup;
			}

			crt::memcpy(&my_pdpt_table[target_va.pdpte_idx], &new_mem_pdpt_table[new_mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

			goto cleanup;
		}

		status = map_4kb_page(my_pdpt_table[target_va.pdpte_idx].page_frame_number << 12, (void*&)my_pde_table, 0);
		if (status != status_success)
			goto cleanup;
		status = map_4kb_page(new_mem_pdpt_table[new_mem_va.pdpte_idx].page_frame_number << 12, (void*&)new_mem_pde_table, 0);
		if (status != status_success)
			goto cleanup;

		if (my_pde_table[target_va.pde_idx].large_page || new_mem_pde_table[new_mem_va.pde_idx].large_page) {
			if (!my_pde_table[target_va.pde_idx].large_page || !new_mem_pde_table[new_mem_va.pde_idx].large_page) {
				status = status_paging_wrong_granularity;
				goto cleanup;
			}

			crt::memcpy(&my_pde_table[target_va.pde_idx], &new_mem_pde_table[new_mem_va.pde_idx], sizeof(pde_2mb_64));

			goto cleanup;
		}

		status = map_4kb_page(my_pde_table[target_va.pde_idx].page_frame_number << 12, (void*&)my_pte_table, 0);
		if (status != status_success)
			goto cleanup;
		status = map_4kb_page(new_mem_pde_table[new_mem_va.pde_idx].page_frame_number << 12, (void*&)new_mem_pte_table, 0);
		if (status != status_success)
			goto cleanup;

		crt::memcpy(&my_pte_table[target_va.pte_idx], &new_mem_pte_table[new_mem_va.pte_idx], sizeof(pte_64));

		goto cleanup;
	cleanup:
		__invlpg(target_address);

		safely_unmap_4kb_page(new_mem_pml4_table);
		safely_unmap_4kb_page(new_mem_pdpt_table);
		safely_unmap_4kb_page(new_mem_pde_table);
		safely_unmap_4kb_page(new_mem_pte_table);

		safely_unmap_4kb_page(my_pml4_table);
		safely_unmap_4kb_page(my_pdpt_table);
		safely_unmap_4kb_page(my_pde_table);
		safely_unmap_4kb_page(my_pte_table);

		return status;
	}

	project_status restore_virtual_address_mapping(void* target_address, uint64_t mem_cr3_u64) {
		project_status status = status_success;
		remapped_entry_t* remapping_entry = 0;
		restorable_until restorable_level;

		va_64 mem_va = { 0 };
		cr3 mem_cr3 = { 0 };

		pml4e_64* my_pml4_table = 0;
		pdpte_64* my_pdpt_table = 0;
		pde_64* my_pde_table = 0;

		pml4e_64* mapped_pml4_table = 0;
		pdpte_64* mapped_pdpt_table = 0;
		pde_64* mapped_pde_table = 0;

		mem_va.flags = (uint64_t)target_address;
		mem_cr3.flags = mem_cr3_u64;

		status = get_remapping_entry(target_address, remapping_entry);
		if (status != status_remapping_entry_found)
			goto cleanup;

		status = get_max_restorable_level(remapping_entry, restorable_level);
		if (status != status_success)
			goto cleanup;

		my_pml4_table = page_tables.pml4_table;

		status = map_4kb_page(mem_cr3.address_of_page_directory << 12, (void*&)mapped_pml4_table, 0);
		if (status != status_success)
			goto cleanup;

		status = map_4kb_page(mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12, (void*&)mapped_pdpt_table, 0);
		if (status != status_success)
			goto cleanup;

		if (remapping_entry->pdpt_table.large_page) {
			switch (restorable_level) {
			case pdpt_table_removeable: {

				// First restore the memory mapping
				my_pml4_table[remapping_entry->remapped_va.pml4e_idx].page_frame_number = mapped_pml4_table[mem_va.pml4e_idx].page_frame_number;

				// Then free our structures
				pt_manager::safely_free_pdpt_table(&page_tables, (pdpte_64*)remapping_entry->pdpt_table.table);
				remove_remapping_entry(remapping_entry);
				goto cleanup;
			}
			case pde_table_removeable:
			case pte_table_removeable:
			case nothing_removeable: {
				// We can't free anything unfortunately
				remove_remapping_entry(remapping_entry);
				goto cleanup;
			}
			}
		}

		status = map_4kb_page(mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12, (void*&)mapped_pde_table, 0);
		if (status != status_success)
			goto cleanup;

		if (remapping_entry->pd_table.large_page) {
			switch (restorable_level) {
			case pdpt_table_removeable: {

				// First restore the memory mapping
				my_pml4_table[remapping_entry->remapped_va.pml4e_idx].page_frame_number = mapped_pml4_table[mem_va.pml4e_idx].page_frame_number;

				// Then free our structures
				pt_manager::safely_free_pdpt_table(&page_tables, (pdpte_64*)remapping_entry->pdpt_table.table);
				pt_manager::safely_free_pd_table(&page_tables, (pde_64*)remapping_entry->pd_table.table);

				remove_remapping_entry(remapping_entry);
				goto cleanup;
			}
			case pde_table_removeable: {
				my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;

				my_pdpt_table[remapping_entry->remapped_va.pdpte_idx].page_frame_number = mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number;

				pt_manager::safely_free_pd_table(&page_tables, (pde_64*)remapping_entry->pd_table.table);

				remove_remapping_entry(remapping_entry);
				goto cleanup;
			}
			case pte_table_removeable:
			case nothing_removeable: {
				// We can't free anything unfortunately
				remove_remapping_entry(remapping_entry);
				goto cleanup;
			}
			}
		}

		switch (restorable_level) {
		case pdpt_table_removeable: {

			// First restore the memory mapping
			my_pml4_table[remapping_entry->remapped_va.pml4e_idx].page_frame_number = mapped_pml4_table[mem_va.pml4e_idx].page_frame_number;

			// Then free our structures
			pt_manager::safely_free_pdpt_table(&page_tables, (pdpte_64*)remapping_entry->pdpt_table.table);
			pt_manager::safely_free_pd_table(&page_tables, (pde_64*)remapping_entry->pd_table.table);
			pt_manager::safely_free_pt_table(&page_tables, (pte_64*)remapping_entry->pt_table);

			remove_remapping_entry(remapping_entry);
			goto cleanup;
		}
		case pde_table_removeable: {
			my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;

			my_pdpt_table[remapping_entry->remapped_va.pdpte_idx].page_frame_number = mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number;

			pt_manager::safely_free_pd_table(&page_tables, (pde_64*)remapping_entry->pd_table.table);
			pt_manager::safely_free_pt_table(&page_tables, (pte_64*)remapping_entry->pt_table);

			remove_remapping_entry(remapping_entry);
			goto cleanup;
		}
		case pte_table_removeable: {
			my_pde_table = (pde_64*)remapping_entry->pd_table.table;

			my_pde_table[remapping_entry->remapped_va.pde_idx].page_frame_number = mapped_pde_table[mem_va.pde_idx].page_frame_number;

			pt_manager::safely_free_pt_table(&page_tables, (pte_64*)remapping_entry->pt_table);

			remove_remapping_entry(remapping_entry);
			goto cleanup;
		}
		case nothing_removeable: {
			// We can't free anything unfortunately
			remove_remapping_entry(remapping_entry);
			goto cleanup;
		}
		}

	cleanup:
		safely_unmap_4kb_page(mapped_pml4_table);
		safely_unmap_4kb_page(mapped_pdpt_table);
		safely_unmap_4kb_page(mapped_pde_table);

		__invlpg(target_address);

		return status;
	}

	project_status ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64) {
		project_status status = status_success;
		uint64_t copied_bytes = 0;

		_cli();
		uint64_t old_cr3 = __readcr3();
		__writecr3(constructed_cr3.flags);

		while (copied_bytes < size) {
			void* current_target = (void*)((uint64_t)target_address + copied_bytes);
			uint64_t ensured_size = 0;

			status = ensure_memory_mapping(current_target, mem_cr3_u64, &ensured_size);
			if (status != status_success) {
				__writecr3(old_cr3);
				_sti();
				return status;
			}

			copied_bytes += ensured_size;
		}

		__writecr3(old_cr3);
		_sti();
		return status;
	}

	project_status unset_global_flag_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64) {
		project_status status = status_success;
		uint64_t covered_bytes = 0;

		_cli();
		uint64_t old_cr3 = __readcr3();
		__writecr3(constructed_cr3.flags);

		while (covered_bytes < size) {
			void* current_target = (void*)((uint64_t)target_address + covered_bytes);
			uint64_t ensured_size = 0;

			status = unset_global_flag(current_target, mem_cr3_u64, &ensured_size);
			if (status != status_success) {
				__writecr3(old_cr3);
				_sti();
				return status;
			}

			covered_bytes += ensured_size;
		}

		__writecr3(old_cr3);
		_sti();
		return status;
	}

	/*
		Exposed tests
	*/

	project_status stress_test_memory_copy(void) {
		uint64_t test_size = PAGE_SIZE * 10;
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;
		uint64_t curr_cr3 = 0;

		max_addr.QuadPart = MAXULONG64;

		void* pool = ExAllocatePool(NonPagedPool, test_size);
		void* contiguous_mem = MmAllocateContiguousMemory(test_size, max_addr);

		if (!pool || !contiguous_mem)
			return status_memory_allocation_failed;

		_cli();
		curr_cr3 = __readcr3();
		__writecr3(constructed_cr3.flags);

		for (int i = 0; i < stress_test_count; i++) {
			memset(contiguous_mem, i, test_size);
			crt::memcpy(pool, contiguous_mem, test_size);

			status = copy_virtual_memory(contiguous_mem, pool, test_size, __readcr3(), __readcr3());
			if (status != status_success) {
				_sti();
				__writecr3(curr_cr3);
				goto cleanup;
			}

			if (crt::memcmp(pool, contiguous_mem, test_size) != 0) {
				status = status_data_mismatch;
				_sti();
				__writecr3(curr_cr3);
				goto cleanup;
			}
		}

		status = status_success;
		_sti();
		__writecr3(curr_cr3);

	cleanup:

		if (pool) ExFreePool(pool);
		if (contiguous_mem) MmFreeContiguousMemory(contiguous_mem);

		if (status == status_success) {
			project_log_info("Memory copying stress test finished successfully");
		}

		return status;
	}

	project_status stress_test_memory_remapping(void) {
		project_status status = status_success;
		PHYSICAL_ADDRESS max_addr = { 0 };
		max_addr.QuadPart = MAXULONG64;
		void* mema = 0;
		void* memb = 0;
		uint64_t curr_cr3 = 0;

		mema = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		memb = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		if (!mema || !memb) {
			status = status_memory_allocation_failed;
			goto cleanup;
		}

		crt::memset(mema, 0xa, PAGE_SIZE);
		crt::memset(memb, 0xb, PAGE_SIZE);

		_cli();
		curr_cr3 = __readcr3();
		__writecr3(constructed_cr3.flags);

		status = overwrite_virtual_address_mapping(mema, memb, kernel_cr3.flags, kernel_cr3.flags);
		if (status != status_success)
			goto cleanup;

		if (crt::memcmp(mema, memb, PAGE_SIZE) == 0) {
			_sti();
			project_log_info("Memory remapping stress test finished successfully");
			_cli();
		}
		else {
			status = status_data_mismatch;
			goto cleanup;
		}

		// Restore system mapping and read again, it should be
		// different now
		status = restore_virtual_address_mapping(mema, kernel_cr3.flags);
		if (status != status_success)
			goto cleanup;

		if (crt::memcmp(mema, memb, PAGE_SIZE) != 0) {
			_sti();
			project_log_info("Memory remapping restoring stress test finished successfully");
			_cli();
		}
		else {
			status = status_data_mismatch;
			goto cleanup;
		}

	cleanup:
		_sti();
		if (curr_cr3) {
			__writecr3(curr_cr3);
		}

		if (mema) MmFreeContiguousMemory(mema);
		if (memb) MmFreeContiguousMemory(memb);

		return status;
	}
};