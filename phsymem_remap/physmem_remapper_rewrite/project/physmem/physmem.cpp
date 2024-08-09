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
			// TO DO:
			// Add support checks that determine whether the systems
			// supports all our needs
			cr4 curr_cr4;
			curr_cr4.flags = __readcr4();

			if (curr_cr4.linear_addresses_57_bit) {
				project_log_error("There is no support for 5 level paging");
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

			memcpy(physmem.page_tables.pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

			physmem.constructed_cr3.flags = physmem.kernel_cr3.flags;
			physmem.constructed_cr3.address_of_page_directory = win_get_physical_address(physmem.page_tables.pml4_table) >> 12;
			if (!physmem.constructed_cr3.address_of_page_directory)
				return status_win_address_translation_failed;

			return status_success;
		}

		uint64_t calculate_physical_memory_base(uint64_t pml4e_idx) {
			// Shift the pml4 index right 36 bits to get the virtual address of the first byte of the 512 gb we mapped
			return (pml4e_idx << (9 + 9 + 9 + 12));
		}

		project_status map_full_system_physical_memory(uint32_t free_pml4_idx) {
			page_tables_t* page_tables = &physmem.page_tables;

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
			page_tables_t* page_tables = &physmem.page_tables;

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
		project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t& remaining_bytes) {
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
				remaining_bytes = 0x40000000 - va.offset_1gb;

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
				remaining_bytes = 0x200000 - va.offset_2mb;

				return status;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_entry->page_frame_number << 12));
			mapped_pte_entry = &mapped_pte_table[va.pte_idx];
			if (!mapped_pte_entry->present) {
				status = status_paging_entry_not_present;
				return status;
			}

			physical_address = (mapped_pte_entry->page_frame_number << 12) + va.offset_4kb;
			remaining_bytes = 0x1000 - va.offset_4kb;

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
				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, src_remaining);
				if (status != status_success)
					break;
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, dst_remaining);
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
				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, src_remaining);
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
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, dst_remaining);
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

	namespace testing {
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
			//runtime::copy_memory_from_constructed_cr3((void*)&a, (void*)&c, sizeof(uint64_t), curr);

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