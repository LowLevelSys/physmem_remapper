#include "physmem.hpp"

#include "../interrupts/interrupts.hpp"
#include "../project_utility.hpp"

namespace physmem {
	/*
		Global variables
	*/
	physmem_t physmem;

	namespace support {
		project_status is_physmem_supported(void) {
			// Add support checks that determine whether the systems
			// supports all our needs

			// Only AMD or INTEL processors are supported
			char vendor[13] = { 0 };
			cpuidsplit_t vendor_cpuid_data;
			__cpuid((int*)&vendor_cpuid_data, 0);
			((int*)vendor)[0] = vendor_cpuid_data.ebx;
			((int*)vendor)[1] = vendor_cpuid_data.edx;
			((int*)vendor)[2] = vendor_cpuid_data.ecx;
			if ((strncmp(vendor, "GenuineIntel", 12) != 0) &&
				(strncmp(vendor, "AuthenticAMD", 12) != 0)) {
				project_log_error("Only INTEL and AMD are supported");
				return status_not_supported;
			}

			// Abort on 5 level paging
			cr4 curr_cr4;
			curr_cr4.flags = __readcr4();
			if (curr_cr4.linear_addresses_57_bit) {
				project_log_error("There is no support for 5 level paging");
				return status_not_supported;
			}

			// Since we map 512 gb of physical memory to 2MB pages they should be supporte -.-
			cpuid_eax_01 cpuid_1;
			__cpuid((int*)(&cpuid_1), 1);
			if (!cpuid_1.cpuid_feature_information_edx.physical_address_extension) {
				project_log_error("2MB pages have to be supported");
				return status_not_supported;
			}

			// SSE2 support should be enable as we use mfence etc
			if (!cpuid_1.cpuid_feature_information_edx.sse2_support) {
				project_log_error("Too old instruction set");
				return status_not_supported;
			}

			return status_success;
		}
	};

	namespace page_table_initialization {
		void* allocate_zero_table(PHYSICAL_ADDRESS max_addr) {
			void* table = (void*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

			if (table)
				memset(table, 0, PAGE_SIZE);

			return table;
		}

		project_status allocate_page_tables(void) {
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			physmem.page_tables = (page_tables_t*)MmAllocateContiguousMemory(sizeof(page_tables_t), max_addr);
			if(!physmem.page_tables)
				return status_memory_allocation_failed;

			memset(physmem.page_tables, 0, sizeof(page_tables_t));

			for (uint64_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
				physmem.remapping_tables.pdpt_table[i] = (pdpte_64*)allocate_zero_table(max_addr);
				physmem.remapping_tables.pd_table[i] = (pde_64*)allocate_zero_table(max_addr);
				physmem.remapping_tables.pt_table[i] = (pte_64*)allocate_zero_table(max_addr);

				if (!physmem.remapping_tables.pdpt_table[i] || !physmem.remapping_tables.pd_table[i] || !physmem.remapping_tables.pt_table[i])
					return status_memory_allocation_failed;
			}

			return status_success;
		}

		project_status copy_kernel_page_tables(void) {
			pml4e_64* kernel_pml4_page_table = 0;

			physmem.kernel_cr3.flags = utility::get_cr3(4);
			if (!physmem.kernel_cr3.flags)
				return status_cr3_not_found;

			kernel_pml4_page_table = (pml4e_64*)win_get_virtual_address(physmem.kernel_cr3.address_of_page_directory << 12);
			if (!kernel_pml4_page_table)
				return status_win_address_translation_failed;

			memcpy(physmem.page_tables->pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

			physmem.constructed_cr3.flags = physmem.kernel_cr3.flags;
			physmem.constructed_cr3.address_of_page_directory = win_get_physical_address(physmem.page_tables->pml4_table) >> 12;
			if (!physmem.constructed_cr3.address_of_page_directory)
				return status_win_address_translation_failed;

			return status_success;
		}

		uint64_t calculate_physical_memory_base(uint64_t pml4e_idx) {
			// Shift the pml4 index right 36 bits to get the virtual address of the first byte of the 512 gb we mapped
			return (pml4e_idx << (9 + 9 + 9 + 12));
		}

		project_status map_full_system_physical_memory(uint32_t free_pml4_idx) {
			page_tables_t* page_tables = physmem.page_tables;

			// TO DO:
			// Dynamically determine the range of physical memory this pc has

			// Map the first 512 gb of physical memory; If any user has more than 512 gb of memory just kill yourselfes ig?
			page_tables->pml4_table[free_pml4_idx].present = 1;
			page_tables->pml4_table[free_pml4_idx].write = 1;
			page_tables->pml4_table[free_pml4_idx].page_frame_number = win_get_physical_address(&page_tables->pdpt_table) >> 12;
			if (!page_tables->pml4_table[free_pml4_idx].page_frame_number)
				return status_win_address_translation_failed;

			for (uint64_t i = 0; i < PAGE_TABLE_ENTRY_COUNT; i++) {
				page_tables->pdpt_table[i].present = 1;
				page_tables->pdpt_table[i].write = 1;
				page_tables->pdpt_table[i].page_frame_number = win_get_physical_address(&page_tables->pd_2mb_table[i]) >> 12;
				if (!page_tables->pdpt_table[i].page_frame_number)
					return status_win_address_translation_failed;

				for (uint64_t j = 0; j < PAGE_TABLE_ENTRY_COUNT; j++) {
					page_tables->pd_2mb_table[i][j].present = 1;
					page_tables->pd_2mb_table[i][j].write = 1;
					page_tables->pd_2mb_table[i][j].large_page = 1;
					page_tables->pd_2mb_table[i][j].page_frame_number = (i << 9) + j;
				}
			}

			return status_success;
		}

		project_status construct_my_page_tables(void) {
			page_tables_t* page_tables = physmem.page_tables;

			uint32_t free_pml4_idx = pt_helpers::find_free_pml4e_index(page_tables->pml4_table);
			if (!pt_helpers::is_index_valid(free_pml4_idx))
				return status_invalid_paging_idx;

			project_status status = map_full_system_physical_memory(free_pml4_idx);
			if (status != status_success)
				return status;

			physmem.mapped_physical_mem_base = calculate_physical_memory_base(free_pml4_idx);
			if (!physmem.mapped_physical_mem_base)
				return status_failure; // Can't happen basically

			return status_success;
		}

		project_status initialize_page_tables(void) {
			project_status status = page_table_initialization::allocate_page_tables();
			if (status != status_success)
				return status;

			status = page_table_initialization::copy_kernel_page_tables();
			if (status != status_success)
				return status;

			status = page_table_initialization::construct_my_page_tables();
			if (status != status_success)
				return status;

			return status;
		}
	}

	namespace util {
		bool is_initialized(void) {
			return physmem.initialized;
		}

		cr3 get_constructed_cr3(void) {
			return physmem.constructed_cr3;
		}

		cr3 get_system_cr3(void) {
			return physmem.kernel_cr3;
		}
	};

	/*
		Exposed core runtime API's
	*/
	namespace runtime {
		project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t* remaining_bytes) {
			cr3 target_cr3 = { 0 };
			va_64_t va = { 0 };

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

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (target_cr3.address_of_page_directory << 12));
			mapped_pml4_entry = &mapped_pml4_table[va.pml4e_idx];
			if (!mapped_pml4_entry->present) {
				status = status_paging_entry_not_present;
				return status;
			}

			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_entry->page_frame_number << 12));
			mapped_pdpt_entry = &mapped_pdpt_table[va.pdpte_idx];
			if (!mapped_pdpt_entry->present) {
				status = status_paging_entry_not_present;
				return status;
			}

			if (mapped_pdpt_entry->large_page) {
				pdpte_1gb_64 mapped_pdpte_1gb_entry;
				mapped_pdpte_1gb_entry.flags = mapped_pdpt_entry->flags;

				physical_address = (mapped_pdpte_1gb_entry.page_frame_number << 30) + va.offset_1gb;
				if(remaining_bytes)
					*remaining_bytes = 0x40000000 - va.offset_1gb;
	
				return status;
			}


			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_entry->page_frame_number << 12));
			mapped_pde_entry = &mapped_pde_table[va.pde_idx];
			if (!mapped_pde_entry->present) {
				status = status_paging_entry_not_present;
				return status;
			}

			if (mapped_pde_entry->large_page) {
				pde_2mb_64 mapped_pde_2mb_entry;
				mapped_pde_2mb_entry.flags = mapped_pde_entry->flags;

				physical_address = (mapped_pde_2mb_entry.page_frame_number << 21) + va.offset_2mb;
				if (remaining_bytes)
					*remaining_bytes = 0x200000 - va.offset_2mb;

				return status;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_entry->page_frame_number << 12));
			mapped_pte_entry = &mapped_pte_table[va.pte_idx];
			if (!mapped_pte_entry->present) {
				status = status_paging_entry_not_present;
				return status;
			}

			physical_address = (mapped_pte_entry->page_frame_number << 12) + va.offset_4kb;
			if (remaining_bytes)
				*remaining_bytes = 0x1000 - va.offset_4kb;
	
			return status;
		}

		void copy_physical_memory(uint64_t dst_physical, uint64_t src_physical, uint64_t size) {
			void* virtual_src = 0;
			void* virtual_dst = 0;

			virtual_src = (void*)(src_physical + physmem.mapped_physical_mem_base);
			virtual_dst = (void*)(dst_physical + physmem.mapped_physical_mem_base);

			memcpy(virtual_dst, virtual_src, size);
		}

		project_status copy_virtual_memory(void* dst, void* src, uint64_t size, uint64_t dst_cr3, uint64_t src_cr3) {
			project_status status = status_success;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_src = 0;
			uint64_t current_physical_dst = 0;
			uint64_t src_remaining = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				// Translate both the src and dst into physical addresses
				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, &src_remaining);
				if (status != status_success)
					break;
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, &dst_remaining);
				if (status != status_success)
					break;

				current_virtual_src = (void*)(current_physical_src + physmem.mapped_physical_mem_base);
				current_virtual_dst = (void*)(current_physical_dst + physmem.mapped_physical_mem_base);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, src_remaining);
				copyable_size = min(copyable_size, dst_remaining);

				// Then copy the mem
				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
			}

			return status;
		}

		project_status copy_memory_to_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t src_cr3) {
			project_status status = status_success;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_src = 0;
			uint64_t src_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				// Translate the src into a physical address
				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, &src_remaining);
				if (status != status_success)
					break;

				current_virtual_src = (void*)(current_physical_src + physmem.mapped_physical_mem_base);
				current_virtual_dst = (void*)((uint64_t)dst + copied_bytes);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, src_remaining);

				// Then copy the mem
				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
			}

			return status;
		}

		project_status copy_memory_from_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t dst_cr3) {
			project_status status = status_success;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_dst = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				// Translate the dst into a physical address
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, &dst_remaining);
				if (status != status_success)
					break;

				current_virtual_src = (void*)((uint64_t)src + copied_bytes);
				current_virtual_dst = (void*)(current_physical_dst + physmem.mapped_physical_mem_base);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, dst_remaining);

				// Then copy the mem
				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
			}

			return status;
		}
	};

	/*
		The exposed API's in here are designed for initialization
	*/
	namespace remapping {

		project_status get_remapping_entry(void* mem, remapped_entry_t*& remapping_entry) {
			project_status status = status_remapping_entry_found;
			va_64_t target_va = { 0 };
			remapped_entry_t dummy = { 0 };
			remapped_entry_t* curr_closest_entry = &dummy;

			target_va.flags = (uint64_t)mem;

			for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
				remapped_entry_t* curr_entry = &physmem.remapping_tables.remapping_list[i];

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

			for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
				remapped_entry_t* curr_entry = &physmem.remapping_tables.remapping_list[i];

				// Check whether the current entry is present/occupied
				if (curr_entry->used)
					continue;

				memcpy(curr_entry, &new_entry, sizeof(remapped_entry_t));
				curr_entry->used = true;

				return status_success;
			}

			return status_remapping_list_full;
		}

		project_status get_max_remapping_level(remapped_entry_t* remapping_entry, uint64_t target_address, usable_until_t& usable_level) {
			va_64_t target_va;
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


		project_status ensure_memory_mapping_without_previous_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size) {
			if (!ensured_size || !mem || !mem_cr3_u64)
				return status_invalid_parameter;

			va_64_t mem_va = { 0 };
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

			my_pml4_table = physmem.page_tables->pml4_table;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12));

			if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
				my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
				if (!my_pdpt_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}

				pdpte_1gb_64* my_1gb_pdpt_table = (pdpte_1gb_64*)my_pdpt_table;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_1gb_pdpt_table, pdpt_phys) != status_success)
					goto cleanup;

				memcpy(my_1gb_pdpt_table, mapped_pdpt_table, sizeof(pdpte_1gb_64) * 512);
				memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

				my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

				// Create a new remapping entry
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = true;
				new_entry.pdpt_table.table = my_pdpt_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x40000000 - mem_va.offset_1gb;

				goto cleanup;
			}

			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));

			if (mapped_pde_table[mem_va.pde_idx].large_page) {
				my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
				if (!my_pdpt_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}

				my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
				if (!my_pde_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}

				pde_2mb_64* my_2mb_pd_table = (pde_2mb_64*)my_pde_table;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pdpt_table, pdpt_phys) != status_success)
					goto cleanup;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys) != status_success)
					goto cleanup;


				memcpy(my_2mb_pd_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
				memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
				memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;
				my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

				// Create a new remapping entry
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = my_pdpt_table;

				new_entry.pd_table.large_page = true;
				new_entry.pd_table.table = my_pde_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x200000 - mem_va.offset_2mb;

				goto cleanup;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_table[mem_va.pde_idx].page_frame_number << 12));

			my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
			if (!my_pdpt_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
			if (!my_pde_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
			if (!my_pte_table) {
				status = status_invalid_my_page_table;
				goto cleanup;
			}

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pdpt_table, pdpt_phys);
			if (status != status_success)
				goto cleanup;

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
			if (status != status_success)
				goto cleanup;

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
			if (status != status_success)
				goto cleanup;

			memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
			memcpy(my_pde_table, mapped_pde_table, sizeof(pde_64) * 512);
			memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
			memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

			my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;
			my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;
			my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

			// Create a new remapping entry
			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = my_pdpt_table;

			new_entry.pd_table.large_page = false;
			new_entry.pd_table.table = my_pde_table;

			new_entry.pt_table = my_pte_table;

			status = add_remapping_entry(new_entry);

			*ensured_size = 0x1000 - mem_va.offset_4kb;

		cleanup:

			__invlpg(mem);

			return status;
		}

		project_status ensure_memory_mapping_with_previous_mapping(void* mem, uint64_t mem_cr3_u64, remapped_entry_t* remapping_entry, uint64_t* ensured_size) {
			if (!ensured_size || !mem || !mem_cr3_u64 || !remapping_entry)
				return status_invalid_parameter;

			project_status status = status_success;
			va_64_t mem_va = { 0 };
			cr3 mem_cr3 = { 0 };

			mem_va.flags = (uint64_t)mem;
			mem_cr3.flags = mem_cr3_u64;

			// Pointers to mapped system tables
			pml4e_64* mapped_pml4_table = 0;
			pdpte_64* mapped_pdpt_table = 0;
			pde_64* mapped_pde_table = 0;
			pte_64* mapped_pte_table = 0;

			// Pointers to our tables
			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;

			usable_until_t max_usable = non_valid;
			status = get_max_remapping_level(remapping_entry, (uint64_t)mem, max_usable);
			if (status != status_success)
				goto cleanup;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12));

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


					// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
					memcpy(&my_pdpt_table[mem_va.pdpte_idx], &mapped_pdpt_table[mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = true;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x40000000 - mem_va.offset_1gb;

					goto cleanup;
				}
				}
			}

			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));

			if (mapped_pde_table[mem_va.pde_idx].large_page) {
				switch (max_usable) {
				case pdpt_table_valid: {
					my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
					if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
						status = status_address_already_remapped;
						goto cleanup;
					}

					my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
					if (!my_pde_table) {
						status = status_invalid_my_page_table;
						goto cleanup;
					}


					uint64_t pd_phys;
					status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
					if (status != status_success)
						goto cleanup;

					// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
					memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
					my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = false;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					new_entry.pd_table.large_page = true;
					new_entry.pd_table.table = my_pde_table;

					status = add_remapping_entry(new_entry);

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

					// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
					memcpy(&my_2mb_pde_table[mem_va.pde_idx], &mapped_pde_table[mem_va.pde_idx], sizeof(pde_2mb_64));

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = false;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					new_entry.pd_table.large_page = true;
					new_entry.pd_table.table = remapping_entry->pd_table.table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x200000 - mem_va.offset_2mb;

					goto cleanup;
				}
				}
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_table[mem_va.pde_idx].page_frame_number << 12));

			switch (max_usable) {
			case pdpt_table_valid: {
				my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
				if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
					status = status_address_already_remapped;
					goto cleanup;
				}
				my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
				if (!my_pde_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}
				my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
				if (!my_pte_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}

				uint64_t pd_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
				if (status != status_success)
					goto cleanup;

				uint64_t pt_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
				if (status != status_success)
					goto cleanup;


				// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
				memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
				memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
				my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;
				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;


				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = my_pde_table;

				new_entry.pt_table = my_pte_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			case pde_table_valid: {
				my_pde_table = (pde_64*)remapping_entry->pd_table.table;
				if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
					status = status_address_already_remapped;
					goto cleanup;
				}

				my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
				if (!my_pte_table) {
					status = status_invalid_my_page_table;
					goto cleanup;
				}

				uint64_t pt_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
				if (status != status_success)
					goto cleanup;


				// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
				memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
				my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;


				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				new_entry.pt_table = my_pte_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			case pte_table_valid: {
				my_pte_table = (pte_64*)remapping_entry->pt_table;
				if (mem_va.pte_idx == remapping_entry->remapped_va.pte_idx) {
					status = status_address_already_remapped;
					goto cleanup;
				}


				memcpy(&my_pte_table[mem_va.pte_idx], &mapped_pte_table[mem_va.pte_idx], sizeof(pte_64));

				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				new_entry.pt_table = remapping_entry->pt_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			}

		cleanup:

			__invlpg(mem);
			return status;
		}

		project_status ensure_memory_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size = 0) {
			if (!mem || !mem_cr3_u64)
				return status_invalid_parameter;

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

		/*
			Exposed API's
		*/
		project_status ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64) {
			project_status status = status_success;
			uint64_t copied_bytes = 0;

			_cli();
			uint64_t curr_cr3 = __readcr3();
			__writecr3(physmem.constructed_cr3.flags);
			_mm_mfence();

			while (copied_bytes < size) {
				void* current_target = (void*)((uint64_t)target_address + copied_bytes);
				uint64_t ensured_size = 0;

				status = ensure_memory_mapping(current_target, mem_cr3_u64, &ensured_size);
				if (status != status_success) {
					_mm_mfence();
					__writecr3(curr_cr3);
					_sti();

					return status;
				}

				copied_bytes += ensured_size;
			}

			_mm_mfence();
			__writecr3(curr_cr3);
			_sti();

			return status;
		}

		project_status overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64) {
			if (PAGE_ALIGN(target_address) != target_address ||
				PAGE_ALIGN(new_memory) != new_memory)
				return status_non_aligned;

			_cli();
			uint64_t old_cr3 = __readcr3();
			__writecr3(physmem.constructed_cr3.flags);
			_mm_mfence();

			project_status status = status_success;

			cr3 new_mem_cr3 = { 0 };

			va_64_t target_va = { 0 };
			va_64_t new_mem_va = { 0 };

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


			my_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (physmem.constructed_cr3.address_of_page_directory << 12));
			new_mem_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (new_mem_cr3.address_of_page_directory << 12));

			my_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (my_pml4_table[target_va.pml4e_idx].page_frame_number << 12));
			new_mem_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (new_mem_pml4_table[new_mem_va.pml4e_idx].page_frame_number << 12));

			if (my_pdpt_table[target_va.pdpte_idx].large_page || new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
				if (!my_pdpt_table[target_va.pdpte_idx].large_page || !new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
					status = status_paging_wrong_granularity;
					goto cleanup;
				}

				memcpy(&my_pdpt_table[target_va.pdpte_idx], &new_mem_pdpt_table[new_mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

				goto cleanup;
			}

			my_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (my_pdpt_table[target_va.pdpte_idx].page_frame_number << 12));
			new_mem_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (new_mem_pdpt_table[new_mem_va.pdpte_idx].page_frame_number << 12));

			if (my_pde_table[target_va.pde_idx].large_page || new_mem_pde_table[new_mem_va.pde_idx].large_page) {
				if (!my_pde_table[target_va.pde_idx].large_page || !new_mem_pde_table[new_mem_va.pde_idx].large_page) {
					status = status_paging_wrong_granularity;
					goto cleanup;
				}

				memcpy(&my_pde_table[target_va.pde_idx], &new_mem_pde_table[new_mem_va.pde_idx], sizeof(pde_2mb_64));

				goto cleanup;
			}


			my_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (my_pde_table[target_va.pde_idx].page_frame_number << 12));
			new_mem_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (new_mem_pde_table[new_mem_va.pde_idx].page_frame_number << 12));

			memcpy(&my_pte_table[target_va.pte_idx], &new_mem_pte_table[new_mem_va.pte_idx], sizeof(pte_64));

		cleanup:
			__invlpg(target_address);

			_mm_mfence();
			__writecr3(old_cr3);
			_sti();

			return status;
		}
	};

	namespace paging_manipulation {
		// NOTE: This only unmaps pte entries
		project_status unmap_paging_entry(void* memory, uint64_t mem_cr3_u64, uint64_t& unmapped_size, uint64_t max_to_be_unmapped_size) {
			if (!memory || !mem_cr3_u64)
				return status_invalid_parameter;

			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + mem_cr3_u64);
			if (!pml4_table[mem_va.pml4e_idx].present || !pml4_table[mem_va.pml4e_idx].page_frame_number)
				return status_paging_entry_not_present; // Ye no fuck that

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table[mem_va.pdpte_idx].present || !pdpt_table[mem_va.pdpte_idx].page_frame_number) {
				unmapped_size = 0x40000000 - mem_va.offset_1gb;
				return status_success;
			}

			if (pdpt_table[mem_va.pdpte_idx].large_page) {
				pdpte_1gb_64* pdpt_1gb_table = (pdpte_1gb_64*)pdpt_table;

				// We do not want to unmap otherwise used mem; In general try to avoid higher paging granularities when calling this function
				if (max_to_be_unmapped_size < (0x40000000 - mem_va.offset_1gb))
					return status_potential_mem_unmapping_overflow;
				

				pdpt_1gb_table[mem_va.pdpte_idx].flags = 0;
				__invlpg(memory);
				unmapped_size = 0x40000000 - mem_va.offset_1gb;

				return status_success;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table[mem_va.pde_idx].present || !pde_table[mem_va.pde_idx].page_frame_number) {
				unmapped_size = 0x200000 - mem_va.offset_2mb;
				return status_success;
			}

			if (pde_table[mem_va.pdpte_idx].large_page) {
				pde_2mb_64* pd_2mb_table = (pde_2mb_64*)pde_table;

				// We do not want to unmap otherwise used mem; In general try to avoid higher paging granularities when calling this function
				if (max_to_be_unmapped_size < (0x200000 - mem_va.offset_2mb))
					return status_potential_mem_unmapping_overflow;
				

				pd_2mb_table[mem_va.pdpte_idx].flags = 0;
				__invlpg(memory);
				unmapped_size = 0x200000 - mem_va.offset_2mb;

				return status_success;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table[mem_va.pte_idx].present || !pte_table[mem_va.pte_idx].page_frame_number) {
				unmapped_size = 0x1000 - mem_va.offset_4kb;
				return status_success;
			}

			pte_table[mem_va.pte_idx].flags = 0;
			__invlpg(memory);
			unmapped_size = 0x1000 - mem_va.offset_4kb;

			return status_success;
		}

		/*
			Exposed API's; ONLY IN HANDLER
		*/
		project_status win_unmap_memory_range(void* memory, uint64_t mem_cr3_u64, uint64_t size) {
			project_status status = status_success;
			uint64_t unmapped_bytes = 0;
			while (unmapped_bytes < size) {
				void* current_target = (void*)((uint64_t)memory + unmapped_bytes);
				uint64_t unmapped_size = 0;
				
				status = unmap_paging_entry(current_target, mem_cr3_u64, unmapped_size, size - unmapped_bytes);
				if (status != status_success)
					return status;

				unmapped_bytes += unmapped_size;
			}

			return status;
		}
	};

	namespace testing {
		/*
			Call from initalization
		*/
		bool memory_copy_test1(void) {
			volatile uint64_t a = 1;
			volatile uint64_t b = 0;

			_cli();
			uint64_t curr = __readcr3();
			__writecr3(physmem.constructed_cr3.flags);
			_mm_mfence();

			volatile uint64_t c = 0;
			runtime::copy_virtual_memory((void*)&b, (void*)&a, sizeof(uint64_t), curr, curr);
			runtime::copy_memory_to_constructed_cr3((void*)&c, (void*)&a, sizeof(uint64_t), curr);

			_mm_mfence();
			__writecr3(curr);
			_sti();

			return a == b;
		}
	};

	project_status init_physmem(void) {

		project_status status = support::is_physmem_supported();
		if (status != status_success)
			return status;

		status = page_table_initialization::initialize_page_tables();
		if (status != status_success)
			return status;

		physmem.initialized = true;

		return status_success;
	};
};