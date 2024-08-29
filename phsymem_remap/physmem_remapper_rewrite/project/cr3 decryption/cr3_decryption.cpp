#include "cr3_decryption.hpp"

namespace cr3_decryption {
	bool initialized = false;

	uint64_t pte_base = 0;
	uint64_t pde_base = 0;
	uint64_t pdpte_base = 0;
	uint64_t pml4e_base = 0;

	uint64_t cr3_ptebase = 0;

	PPHYSICAL_MEMORY_RANGE memory_ranges = 0;
	_MMPFN* mm_pfn_database = 0;

	/*
		Initialization
	*/
	project_status init_eac_cr3_decryption(void) {
		if (!physmem::is_initialized()) {
			project_log_info("Physmem was not initialized!");
			return status_failure;
		}

		// First find MmPfnDataBase
		uint64_t kernel_base;
		project_status status = utility::get_driver_module_base(L"ntoskrnl.exe", (void*&)kernel_base);
		if (status != status_success || !kernel_base) {
			project_log_info("Failed to get kernel base");
			return status_failure;
		}

		// To Do: Add more patterns
		const char* pattern = "\xB9\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x89\x43\x18";
		uint64_t mov_instr = utility::search_pattern_in_section((void*)kernel_base, ".text", pattern, 16 , 0x0) + 5;
		if (!mov_instr) {
			project_log_info("Failed to find MmPfnDataBase pattern");
			return status_failure;
		}
		uint64_t resolved_base = mov_instr + *reinterpret_cast<int32_t*>(mov_instr + 3) + 7;
		mm_pfn_database = *(_MMPFN**)resolved_base;


		cr3 sys_cr3;
		sys_cr3.flags = __readcr3(); // We do not want to use the kernel cr3, but rather the one that our mapper had or any non kernel one ig
		uint64_t phys_system_directory = sys_cr3.address_of_page_directory << 12;
		pml4e_64* system_directory = (pml4e_64*)win_get_virtual_address(phys_system_directory);
		if (!system_directory)
			return status_win_address_translation_failed;

		// Find the self ref entry
		for (uint64_t i = 0; i < 512; i++) {
			if (system_directory[i].page_frame_number != sys_cr3.address_of_page_directory)
				continue;

			pml4e_base = (i + 0x1FFFE00ui64) << 39ui64;
			pdpte_base = (i << 30ui64) + pml4e_base;
			pde_base = (i << 30ui64) + pml4e_base + (i << 21ui64);
			pte_base = (i << 12ui64) + pde_base;

			cr3_ptebase = i * 8 + pte_base;

			break;
		}

		memory_ranges = MmGetPhysicalMemoryRanges();
		if (!memory_ranges) {
			project_log_info("Failed to get physical memory ranges");
			return status_failure;
		}

		initialized = true;

		return status_success;
	}

	/*
		Runtime
	*/
	namespace eproc {
		uint64_t get_cr3(uint64_t target_pid) {
			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
					uint64_t dirbase = i << 12;
					uint64_t pid = 0;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads)
						continue;

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

		uint64_t get_pid(const char* target_process_name) {
			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads)
						continue;

					char image_name[IMAGE_NAME_LENGTH];
					if (physmem::runtime::copy_memory_to_constructed_cr3(&image_name, (void*)(decrypted_eprocess + IMAGE_NAME_OFFSET), IMAGE_NAME_LENGTH, physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!strstr(target_process_name, image_name))
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!pid)
						continue; // Can apperantly happen??

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
					if (status != status_success)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;

					do {
						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
							break;

						wchar_t dll_name_buffer[MAX_PATH] = { 0 };
						char char_dll_name_buffer[MAX_PATH] = { 0 };

						status = physmem::runtime::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dirbase);
						if (status != status_success)
							continue;

						for (uint64_t j = 0; j < entry.BaseDllName.Length / sizeof(wchar_t) && j < MAX_PATH - 1; j++)
							char_dll_name_buffer[j] = (char)dll_name_buffer[j];

						char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

						if (strstr(target_process_name, char_dll_name_buffer)) {
							return pid;
						}

						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);
				}
			}

			logging::root_printf("Failed to find process %s", target_process_name);

			return 0;
		}
	};

	namespace peb {
		/*
			Core API'S
		*/
		project_status get_ldr_data_table_entry(uint64_t target_pid, char* module_name, LDR_DATA_TABLE_ENTRY* module_entry) {
			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads)
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (pid != target_pid)
						continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
					if (status != status_success)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;

					do {
						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
							break;

						wchar_t dll_name_buffer[MAX_PATH] = { 0 };
						char char_dll_name_buffer[MAX_PATH] = { 0 };

						status = physmem::runtime::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dirbase);
						if (status != status_success)
							continue;

						for (uint64_t j = 0; j < entry.BaseDllName.Length / sizeof(wchar_t) && j < MAX_PATH - 1; j++)
							char_dll_name_buffer[j] = (char)dll_name_buffer[j];

						char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

						if (strstr(module_name, char_dll_name_buffer)) {
							memcpy(module_entry, &entry, sizeof(LDR_DATA_TABLE_ENTRY));
							return status;
						}

						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);
				}
			}

			logging::root_printf("Failed to find module %s in process %p", module_name, target_pid);

			return status_failure;
		}

		/*
			Exposed API'S
		*/
		project_status get_data_table_entry_info(uint64_t target_pid, module_info_t* info_array, uint64_t proc_cr3) {
			uint64_t curr_info_entry = (uint64_t)info_array;

			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads)
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (pid != target_pid)
						continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
					if (status != status_success)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;

					do {
						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
							break;

						wchar_t dll_name_buffer[MAX_PATH] = { 0 };
						char char_dll_name_buffer[MAX_PATH] = { 0 };

						status = physmem::runtime::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dirbase);
						if (status != status_success) {
							next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
						}

						for (uint64_t j = 0; j < entry.BaseDllName.Length / sizeof(wchar_t) && j < MAX_PATH - 1; j++)
							char_dll_name_buffer[j] = (char)dll_name_buffer[j];

						char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

						module_info_t info = { 0 };
						info.base = (uint64_t)entry.DllBase;
						info.size = entry.SizeOfImage;
						memcpy(&info.name, &char_dll_name_buffer, min(entry.BaseDllName.Length / sizeof(wchar_t), MAX_PATH - 1));

						status = physmem::runtime::copy_memory_from_constructed_cr3((void*)curr_info_entry, &info, sizeof(module_info_t), proc_cr3);
						if (status != status_success) {
							next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
						}

						curr_info_entry += sizeof(module_info_t);
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);

					return status;
				}
			}

			logging::root_printf("Failed to find data table entry info in process %p", target_pid);

			return status_failure;
		}

		uint64_t get_data_table_entry_count(uint64_t target_pid) {
			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;
					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads)
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (pid != target_pid)
						continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
					if (status != status_success)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;
					uint64_t module_count = 0;

					do {
						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
						{
							return module_count;
						}

						module_count++;
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);

					return module_count;
				}
			}

			logging::root_printf("Failed to find module count in process %p", target_pid);

			return status_failure;
		}

		uint64_t get_module_base(uint64_t target_pid, char* module_name) {
			LDR_DATA_TABLE_ENTRY data_table_entry;

			project_status status = get_ldr_data_table_entry(target_pid, module_name, &data_table_entry);
			if (status != status_success)
				return 0;

			logging::root_printf("%s module base %p", data_table_entry.BaseDllName, data_table_entry.DllBase);

			return (uint64_t)data_table_entry.DllBase;
		}

		uint64_t get_module_size(uint64_t target_pid, char* module_name) {
			LDR_DATA_TABLE_ENTRY data_table_entry;

			project_status status = get_ldr_data_table_entry(target_pid, module_name, &data_table_entry);
			if (status != status_success)
				return 0;

			logging::root_printf("%s module size %p", data_table_entry.BaseDllName, data_table_entry.SizeOfImage);

			return (uint64_t)data_table_entry.SizeOfImage;
		}
	};
};