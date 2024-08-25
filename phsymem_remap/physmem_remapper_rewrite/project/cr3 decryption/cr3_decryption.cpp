#include "cr3_decryption.hpp"

namespace cr3_decryption {
	bool initialized = false;

	uint64_t pte_base = 0;
	uint64_t pde_base = 0;
	uint64_t pdpte_base = 0;
	uint64_t pml4e_base = 0;
	uint64_t self_ref_idx = MAXUINT32;

	PPHYSICAL_MEMORY_RANGE memory_ranges = 0;
	uint64_t mm_pfn_database = 0;

	/*
		Utility
	*/
	bool is_kernel_base(uint64_t addr) {
		IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)addr;

		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(addr + dos_header->e_lfanew);

		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return false;

		if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
			return false;

		IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(addr + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		char* dll_name = (char*)(addr + export_directory->Name);

		if (!strstr(dll_name, "ntoskrnl.exe"))
			return false;

		return true;
	}

	uint64_t get_kernel_base(void) {
		segment_descriptor_register_64 idt = { 0 };
		__sidt(&idt);
		segment_descriptor_interrupt_gate_64* windows_idt = (segment_descriptor_interrupt_gate_64*)idt.base_address;

		segment_descriptor_interrupt_gate_64 isr_divide_error = windows_idt[0];
		uint64_t pfn_KiDivideErrorFault = ((uintptr_t)isr_divide_error.offset_low) |
			(((uintptr_t)isr_divide_error.offset_middle) << 16) |
			(((uintptr_t)isr_divide_error.offset_high) << 32);

		uint64_t aligned_isr = pfn_KiDivideErrorFault & ~(2_MiB - 1);
		uintptr_t address = aligned_isr;

		while (!is_kernel_base(address)) {
			address -= 2_MiB;
		}

		return address;
	}

	/*
		Testing
	*/
	void log_process_cr3s(void) {
		if (!initialized)
			return;

	}

	/*
		Initialization
	*/
	project_status init_eac_cr3_decryption(void) {
		if (!physmem::is_initialized()) {
			project_log_info("Physmem was not initialized!");
			return status_failure;
		}

		// First find MmPfnDataBase
		uint64_t kernel_base = get_kernel_base();
		if (!kernel_base) {
			project_log_info("Failed to get kernel base");
			return status_failure;
		}

		const char* pattern = "\xB9\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x89\x43\x18";
		uint64_t mov_instr = utility::search_pattern_in_section((void*)kernel_base, ".text", pattern, 16 , 0x0) + 5;
		if (!mov_instr) {
			project_log_info("Failed to find MmPfnDataBase pattern");
			return status_failure;
		}
		uint64_t resolved_base = mov_instr + *reinterpret_cast<int32_t*>(mov_instr + 3) + 7;
		mm_pfn_database = *(uint64_t*)resolved_base;


		cr3 sys_cr3;
		sys_cr3.flags = __readcr3();
		uint64_t phys_system_directory = sys_cr3.address_of_page_directory << 12;
		pml4e_64* system_directory = (pml4e_64*)win_get_virtual_address(phys_system_directory);
		if (!system_directory)
			return status_win_address_translation_failed;

		// Find the self ref entry
		for (uint64_t i = 0; i < 512; i++) {
			if (system_directory[i].page_frame_number != sys_cr3.address_of_page_directory)
				continue;

			pte_base = (i + 0x1FFFE00ui64) << 39ui64;
			pde_base = (i << 30ui64) + pte_base;
			pdpte_base = (i << 30ui64) + pte_base + (i << 21ui64);
			pml4e_base = (i << 12ui64) + pdpte_base;
			self_ref_idx = i;
			break;
		}

		memory_ranges = MmGetPhysicalMemoryRanges();
		if (!memory_ranges) {
			project_log_info("Failed to get physical memory ranges");
			return status_failure;
		}

		log_process_cr3s();

		initialized = true;

		return status_success;
	}

	/*
		Runtime
	*/
	uint64_t get_decrypted_cr3(uint64_t target_pid) {
		uint64_t cr3_ptebase = self_ref_idx * 8 + pml4e_base;

		for (uint32_t mem_range_count = 0; mem_range_count < 200; mem_range_count++) {

			if (!memory_ranges[mem_range_count].BaseAddress.QuadPart && 
				!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
				break;

			uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
			uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

			for (auto i = start_pfn; i < end_pfn; i++) {
				_MMPFN cur_mmpfn;
				uint64_t virt_address = mm_pfn_database + (0x30 * i);

				if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)virt_address, sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
					!= status_success)
					continue;

				if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
					continue;

				uint64_t decrypted_eprocess = ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
				uint64_t dirbase = i << 12;
				uint64_t pid = 0;

				if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
					!= status_success)
					continue;

				if (pid != target_pid)
					continue;

				return dirbase;
			}
		}

		return 0;
	}
}