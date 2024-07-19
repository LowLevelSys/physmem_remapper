#pragma once
#pragma warning (disable: 4003)
#include "../driver/driver_um_lib.hpp"

class process_t {
private:
	// 1 Static instance to ensure you don't accidentily use an unitialized or different class with another process loaded or sth.
	static process_t* process_instance;

	physmem_remapper_um_t* physmem_instance = 0;
	bool inited = false;

	// Owner specific data
	uint64_t owner_pid = 0;
	uint64_t owner_cr3 = 0;

	// Target specific data
	uint64_t target_pid = 0;
	uint64_t target_cr3 = 0;

	uint64_t target_module_count = 0;

	module_info_t* target_modules = 0;

	bool init_process(std::string process_name) {

		physmem_instance = physmem_remapper_um_t::init_physmem_remapper_lib();

		if (!physmem_instance) {
			log("Can't init process if the physmem instance is not allocated");
			return false;
		}

		if (!physmem_instance->is_lib_inited()) {
			log("Can't init process if the physmem instance is not initialized");
			return false;
		}

		owner_pid = GetCurrentProcessId();
		if (!owner_pid) {
			log("Failed to get pid of owner process");
			return false;
		}

		owner_cr3 = physmem_instance->get_cr3(owner_pid);
		if (!owner_cr3) {
			log("Failed to get cr3 of owner process");
			return false;
		}

		target_pid = physmem_instance->get_pid_by_name(process_name.c_str());
		if (!target_pid) {
			log("Failed to get pid of target process: %s", process_name.c_str());
			return false;
		}

		// Then get the cr3
		target_cr3 = physmem_instance->get_cr3(target_pid);
		if (!target_cr3) {
			log("Failed to get cr3 of target process: %s", process_name.c_str());
			return false;
		}

		target_module_count = physmem_instance->get_ldr_data_table_entry_count(target_pid);
		if (!target_module_count) {
			log("Failed get target module count");
			return false;
		}

		target_modules = (module_info_t*)malloc(sizeof(module_info_t) * target_module_count);
		if (!target_modules) {
			log("Failed to alloc memory for modules");
			return false;
		}

		// Ensure that the memory is present (mark pte as present)
		memset(target_modules, 0, sizeof(module_info_t) * target_module_count);

		if (!physmem_instance->get_data_table_entry_info(target_pid, target_modules)) {
			log("Failed getting data table entry info");
			return false;
		}


		return true;
	}

public:

	~process_t() {
		delete physmem_instance;
		physmem_instance = 0;
	}

	physmem_remapper_um_t* get_remapper() {
		return process_instance->physmem_instance;
	}

	static process_t* get_inst(std::string process_name) {
		if (!process_instance) {
			process_instance = new process_t();
			if (!process_instance) {
				log("Failed to allocate process instance");
				return 0;
			}

			if (!process_instance->init_process(process_name)) {
				log("Failed to init for process %s", process_name.c_str());
				return 0;
			}
		}

		return process_instance;
	}

	void speed_test(void) {
		std::chrono::steady_clock::time_point start_time, end_time;
		double elapsed_seconds;
		start_time = std::chrono::steady_clock::now();

		char buffer[0x1000];

		uint64_t mod_base = process_instance->get_module_base("notepad.exe");

		for (uint64_t iteration = 0; iteration < 1000; iteration++) {
			physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, (void*)mod_base, &buffer, 0x1000);
		}

		end_time = std::chrono::steady_clock::now();
		elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
		double reads_per_second = 1000.0 / elapsed_seconds;

		log("PAGE_SIZE Read");
		log("Took %f seconds to read PAGE_SIZE bytes 1000 times -> %f reads per second", elapsed_seconds, reads_per_second);

		start_time = std::chrono::steady_clock::now();
		for (uint64_t iteration = 0; iteration < 1000; iteration++) {
			physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, (void*)mod_base, &buffer, 4);
		}

		end_time = std::chrono::steady_clock::now();
		elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
	    reads_per_second = 1000.0 / elapsed_seconds;

		log("4 Byte Read");
		log("Took %f seconds to read 4 bytes 1000 times -> %f reads per second\n", elapsed_seconds, reads_per_second);

	}

	bool read_array(void* dest, void* src, uint64_t size) {
		return physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, src, dest, size);
	}

	bool write_array(void* dest, void* src, uint64_t size) {
		return physmem_instance->copy_virtual_memory(owner_cr3, target_cr3, src, dest, size);
	}

	template <typename t>
	t read(void* src, uint64_t size = sizeof(t)) {
		t buffer{};

		if (!physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, src, &buffer, sizeof(t))) {
			log("Failed to copy memory from src: [%p] to dest: [%p]", (void*)src, &buffer);
			return { 0 };
		}

		return buffer;
	}

	bool write(void* dest, void* src, uint64_t size) {
		return physmem_instance->copy_virtual_memory(owner_cr3, target_cr3, src, dest, size);
	}

	module_info_t get_module(std::string module_name) {
		for (uint64_t i = 0; i < target_module_count - 1; i++) {
			//log("%s", target_modules[i].name);
			if (strstr(module_name.c_str(),target_modules[i].name)) {
				return target_modules[i];
			}
		}

		return { 0 };
	}

	uint64_t get_module_base(std::string module_name) {
		module_info_t module = get_module(module_name);
		return module.base;
	}

	uint64_t get_module_size(std::string module_name) {
		module_info_t module = get_module(module_name);
		return module.size;
	}

	bool remove_apc() {
		bool result = physmem_instance->remove_apc();
		return result;
	}

	bool restore_apc() {
		bool result = physmem_instance->restore_apc();
		return result;
	}

	bool trigger_cow_in_target(void* target_address) {
		return physmem_instance->trigger_cow(target_address, this->target_cr3, this->owner_cr3);
	}

	void revert_cow_trigger_in_target(void* target_address) {
		return physmem_instance->revert_cow_triggering(target_address, this->target_cr3);
	}

	bool find_and_copy_cow_page(void* target_address) {
		return physmem_instance->find_and_copy_cow_page(target_address, this->target_cr3, this->owner_cr3);
	}

	uint64_t get_target_pid(void) {
		return target_pid;
	}
};

process_t* process_t::process_instance = 0;
inline process_t* g_proc;

namespace inject {
	typedef struct memory_allocation_struct {
		void* result;
	};

	typedef struct data_struct {
		int Status;
		uintptr_t dll_main;
		HINSTANCE hmodule;
	};

	// Note: You have to split up the shellcode into junks of 25 bytes

	inline byte memory_allocation_shellcode0[] = {
		0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x0000000000000000 // VirtualAlloc address

		// Jump to the next piece of shellcode
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, imm64 (address of my next shellcode)
		0xFF, 0xE6,													// jmp rsi
	};

	inline byte memory_allocation_shellcode1[] = {
		0x48, 0x31, 0xC9,                        					// xor rcx, rcx

		// Jump to the next piece of shellcode
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, imm64 (address of my next shellcode)
		0xFF, 0xE6,													// jmp rsi
	};

	inline byte memory_allocation_shellcode2[] = {
		0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rdx, 0x0000000000000000 // size to allocate

		// Jump to the next piece of shellcode
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, imm64 (address of my next shellcode)
		0xFF, 0xE6,													// jmp rsi
	};

	inline byte memory_allocation_shellcode3[] = {
		0x49, 0xC7, 0xC0, 0x00, 0x30, 0x00, 0x00,					// mov r8, 0x3000

		// Jump to the next piece of shellcode
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, imm64 (address of my next shellcode)
		0xFF, 0xE6,													// jmp rsi
	};

	inline byte memory_allocation_shellcode4[] = {
		0x49, 0xC7, 0xC1, 0x40, 0x00, 0x00, 0x00,					// mov r9, 0x40

		// Jump to the next piece of shellcode
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, imm64 (address of my next shellcode)
		0xFF, 0xE6,													// jmp rsi
	};

	inline byte memory_allocation_shellcode5[] = {
		0x48, 0x83, 0xEC, 0x20,                  					// sub rsp, 0x20
		0xFF, 0xD3,                              					// call rbx
		0x48, 0x83, 0xC4, 0x20,										// add rsp, 0x20

		// Jump to the next piece of shellcode
		0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, imm64 (address of my next shellcode)
		0xFF, 0xE6,													// jmp rsi
	};

	inline byte memory_allocation_shellcode6[] = {
		// Store the allocated address in some codecave
		0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x0000000000000000

		// Store the allocation
		0xC6, 0x00, 0x00,											// mov byte ptr [rax], 0
		0x48, 0x89, 0x03,                                           // mov [rbx], rax

		0xC3,													    // ret
	};


	inline byte dll_main_invoking_shellcode[92] = {
		0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
		0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
		0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
		0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
	};

	data_struct* remote_data = 0;
	void* remote_dll_invoking_shellcode = 0;

	namespace pe {
		inline byte* load_raw_dll(const char* dll_path) {
			std::ifstream file(dll_path, std::ios::binary | std::ios::ate);
			if (!file) {
				log("Can't open file");
				return 0;
			}

			// Get file size
			std::streamsize size = file.tellg();
			file.seekg(0, std::ios::beg);

			// Allocate buffer and read file
			byte* buffer = new byte[size];
			if (!buffer) {
				throw std::bad_alloc();
			}

			if (!file.read((char*)buffer, size)) {
				delete[] buffer;
				return 0;
			}

			file.close();

			return buffer;
		}

		inline void free_raw_dll(byte* buffer)
		{
			delete[] buffer;
		}

		inline bool is_valid_image(IMAGE_DOS_HEADER* dos_header, IMAGE_NT_HEADERS* nt_headers) {
			if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
				log("Invalid dos header");
				return false;
			}

			if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
				log("Invalid Nt header signature");
				return false;
			}

			if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
				log("Architecture: 0x%llx not compatible", nt_headers->FileHeader.Machine);
				return false;
			}

			return true;
		}

		inline void* rva_va(const std::uintptr_t rva, IMAGE_NT_HEADERS* nt_header, void* local_image) {
			PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(nt_header);

			for (PIMAGE_SECTION_HEADER section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++) {
				if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
					return (unsigned char*)local_image + section->PointerToRawData + (rva - section->VirtualAddress);
				}
			}

			return 0;
		}

		inline bool relocate_image(void* remote_base, void* raw_data, IMAGE_NT_HEADERS* nt_headers) {
			typedef struct _RELOC_ENTRY
			{
				ULONG ToRVA;
				ULONG Size;
				struct
				{
					WORD Offset : 12;
					WORD Type : 4;
				} Item[1];
			} RELOC_ENTRY, * PRELOC_ENTRY;

			uint64_t delta_offset = (uint64_t)remote_base - nt_headers->OptionalHeader.ImageBase;

			if (!delta_offset)
				return true;


			else if (!(nt_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
				return false;


			RELOC_ENTRY* relocation_entry = (RELOC_ENTRY*)rva_va(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_headers, raw_data);
			uint64_t relocation_end = (uint64_t)relocation_entry + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

			if (!relocation_entry)
				return true;


			while ((uint64_t)relocation_entry < relocation_end && relocation_entry->Size) {
				uint32_t records_count = (relocation_entry->Size - 8) >> 1;

				for (uint32_t i = 0ul; i < records_count; i++) {
					WORD fixed_type = (relocation_entry->Item[i].Type);
					WORD shift_delta = (relocation_entry->Item[i].Offset) % 4096;

					if (fixed_type == IMAGE_REL_BASED_ABSOLUTE)
						continue;

					if (fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64) {
						uint64_t fixed_va = (uint64_t)rva_va(relocation_entry->ToRVA, nt_headers, raw_data);

						if (!fixed_va)
							fixed_va = (uint64_t)raw_data;

						*(uint64_t*)(fixed_va + shift_delta) += delta_offset;
					}
				}

				relocation_entry = (PRELOC_ENTRY)((LPBYTE)relocation_entry + relocation_entry->Size);
			}

			return true;
		}

		inline uint64_t resolve_function_address(LPCSTR module_name, LPCSTR function_name) {
			HMODULE handle = LoadLibraryExA(module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);
			if (!handle)
				return 0;

			uint64_t offset = (uint64_t)GetProcAddress(handle, function_name) - (uint64_t)handle;

			FreeLibrary(handle);

			return offset;
		}

		inline bool resolve_imports(void* raw_data, IMAGE_NT_HEADERS* nt_headers) {
			IMAGE_IMPORT_DESCRIPTOR* import_description = (IMAGE_IMPORT_DESCRIPTOR*)rva_va(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_headers, raw_data);

			if (!nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ||
				!nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
				return true;
			}

			LPSTR module_name = 0;
			while ((module_name = (LPSTR)rva_va(import_description->Name, nt_headers, raw_data))) {
				uint64_t base_image = (uint64_t)LoadLibraryA(module_name);

				if (!base_image)
					return false;


				IMAGE_THUNK_DATA* import_header_data = (IMAGE_THUNK_DATA*)rva_va(import_description->FirstThunk, nt_headers, raw_data);

				while (import_header_data->u1.AddressOfData) {
					if (import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)(import_header_data->u1.Ordinal & 0xFFFF));
					}
					else {
						IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)rva_va(import_header_data->u1.AddressOfData, nt_headers, raw_data);
						import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)ibn->Name);
					}

					import_header_data++;
				}
				import_description++;
			}

			return true;
		}

		inline bool copy_headers(void* remote_process_dll_base, void* raw_dll, IMAGE_NT_HEADERS* nt_headers) {
			return g_proc->write(remote_process_dll_base, raw_dll, nt_headers->OptionalHeader.SizeOfHeaders);
		}

		inline bool copy_sections(void* remote_process_dll_base, void* raw_dll, IMAGE_NT_HEADERS* nt_headers) {
			IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);

			for (WORD i = 0; i != nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
				if (!section_header->SizeOfRawData)
					continue;

				void* curr_src = (void*)((uint64_t)raw_dll + section_header->PointerToRawData);
				void* curr_dst = (void*)((uint64_t)remote_process_dll_base + section_header->VirtualAddress);

				if (!g_proc->write(curr_dst, curr_src, section_header->SizeOfRawData)) {
					log("Couldn't copy section %s", section_header->Name);
					return false;
				}
			}

			return true;
		}


		inline bool load_shellcode(void* remote_process_dll_base, IMAGE_NT_HEADERS* nt_headers) {
			/*
				Shellcode:

				sub rsp,38
				mov rax,0000000000000000
				mov [rsp+20],rax
				mov rax,[rsp+20]
				cmp dword ptr [rax],00
				jne 0014FEB6
				mov rax,[rsp+20]
				mov [rax],00000001
				mov rax,[rsp+20]
				mov rax,[rax+08]
				mov [rsp+28],rax
				xor r8d,r8d
				mov edx,00000001
				mov rax,[rsp+20]
				mov rcx,[rax+10]
				call qword ptr [rsp+28]
				mov rax,[rsp+20]
				mov [rax],00000002
				add rsp,38
				ret
			*/

			uint64_t remote_dllmain = (uint64_t)remote_process_dll_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

			remote_dll_invoking_shellcode = (void*)((uint64_t)remote_process_dll_base + (uint64_t)nt_headers->OptionalHeader.SizeOfImage);
			remote_data = (data_struct*)((uint64_t)remote_dll_invoking_shellcode + +sizeof(dll_main_invoking_shellcode) + sizeof(data_struct));

			*(uint64_t*)((uint8_t*)dll_main_invoking_shellcode + 6) = (uint64_t)remote_data;

			data_struct dll_data = { 0 };
			dll_data.dll_main = remote_dllmain;
			dll_data.hmodule = (HINSTANCE)remote_process_dll_base;

			if (!g_proc->write((void*)remote_data, &dll_data, sizeof(dll_data))) {
				log("Couldn't write data to target process");
				return false;
			}

			if (!g_proc->write((void*)remote_dll_invoking_shellcode, dll_main_invoking_shellcode, sizeof(dll_main_invoking_shellcode))) {
				log("Couldn't write shellcode to target process");
				return false;
			}

			return true;
		}

		inline bool invoke_dllmain_shellcode(void* remote_process_dll_base, uint64_t target_pid, IMAGE_NT_HEADERS* nt_headers) {

			char jump_to_shellcode[] = {
				0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,       // mov rax, gs:[0x30]
				0x8B, 0x40, 0x40,                                           // mov eax,[rax+0x40] ; pid
				0x3D, 0xDD, 0xCC, 0xAB, 0x0A,                               // cmp eax, target_pid
				0x75, 0x0C,                                                 // jne ret_label

				// Jump to my handler
				0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov rax, imm64 (address of my asm handler)
				0xFF, 0xE0,                                                 // jmp rax

				// All processes that don't have pid == target_pid (ret_label)
				0xC3                                                        // ret
			};
			char orig_sleep_bytes[sizeof(jump_to_shellcode)] = { 0 };

			*(uint64_t*)((uint8_t*)jump_to_shellcode + 21) = (uint64_t)remote_dll_invoking_shellcode;
			*(uint32_t*)((uint8_t*)jump_to_shellcode + 13) = (uint32_t)target_pid;

			// Safe orig bytes
			if (!g_proc->read_array(orig_sleep_bytes, Sleep, sizeof(orig_sleep_bytes))) {
				log("Failed backup orig sleep bytes");
				return false;
			}

			// Hook Sleep
			if (!g_proc->write(Sleep, &jump_to_shellcode, sizeof(jump_to_shellcode))) {
				log("Failed to hook Sleep to gain execution");
				return false;
			}

			/*
				Wait for DllMain to return
			*/
			data_struct dll_data = { 0 };
			while (!dll_data.Status) {
				dll_data = g_proc->read<data_struct>(remote_data);
			}

			// Unhook Sleep
			if (!g_proc->write(Sleep, &orig_sleep_bytes, sizeof(orig_sleep_bytes))) {
				log("Failed to hook Sleep to gain execution");
				return false;
			}

			return true;
		}
	};

	inline std::vector<void*> get_code_caves(void* base, std::string section_name, uint32_t size, uint64_t count) {
		std::vector<void*> codecaves;

		// Ensure at least some alignment
		if (size < 8)
			size = 8;

		IMAGE_DOS_HEADER* pdos_header = (IMAGE_DOS_HEADER*)base;
		IMAGE_DOS_HEADER dos_header;
		dos_header = g_proc->read<IMAGE_DOS_HEADER>(pdos_header);
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
			log("Invalid DOS header signature\n");
			return codecaves;
		}

		IMAGE_NT_HEADERS* pnt_headers = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos_header.e_lfanew);
		IMAGE_NT_HEADERS nt_headers;
		nt_headers = g_proc->read<IMAGE_NT_HEADERS>(pnt_headers);
		if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
			log("Invalid NT headers signature\n");
			return codecaves;
		}

		IMAGE_SECTION_HEADER* section_headers = new IMAGE_SECTION_HEADER[nt_headers.FileHeader.NumberOfSections];
		g_proc->read_array(section_headers, (IMAGE_SECTION_HEADER*)(pnt_headers + 1), sizeof(IMAGE_SECTION_HEADER) * nt_headers.FileHeader.NumberOfSections);

		uint8_t* local_buffer = new uint8_t[0x1000 + size - 1];
		for (WORD i = 0; i < nt_headers.FileHeader.NumberOfSections; ++i) {
			if (memcmp(section_headers[i].Name, section_name.c_str(), section_name.length() - 1) == 0) {
				uint32_t section_size = section_headers[i].Misc.VirtualSize;
				uint8_t* section_base = (uint8_t*)base + section_headers[i].VirtualAddress;

				for (uint32_t offset = 0; offset < section_size; offset += 0x1000) {
					uint32_t chunk_size = (offset + 0x1000 > section_size) ? section_size - offset : 0x1000;

					if (!g_proc->read_array(local_buffer, section_base + offset, chunk_size)) {
						log("Failed to read .text section chunk");
						continue;
					}

					for (uint32_t j = 0; j < chunk_size; ++j) {
						if (local_buffer[j] == 0xCC || local_buffer[j] == 0x00) {
							uint8_t current_byte = local_buffer[j];
							uint32_t k = 1;
							for (; k < size && j + k < chunk_size; ++k) {
								if (local_buffer[j + k] != current_byte)
									break;
							}

							if (k == size) {
								codecaves.push_back(section_base + offset);
								offset += k - 1; // Move offset to end of the current code cave

								if (codecaves.size() >= count) {
									return codecaves;
								}
							}
						}
					}
				}
			}
		}

		return codecaves;
	}

	inline void* allocate_memory_in_remote_process(uint64_t size) {
		// 25 bytes is the most you will get in KERNEL32.DLL, you have to split your shellcode
		void* remote_dll = (void*)g_proc->get_module_base("KERNEL32.DLL");
		if (!remote_dll) {
			log("Discord is not loaded in the target");
			return 0;
		}
		std::vector<void*> data_code_cave = get_code_caves(remote_dll, ".data", 8, 1);
		if (data_code_cave.size() == 0) {
			log("Failed to find code cave for memory allocation");
			return 0;
		}


		std::vector<void*> shellcode_ptrs = get_code_caves(remote_dll, ".text", 25, 7);
		if(shellcode_ptrs.size() < 7) {
			log("Failed to find code cave for memory allocation");
			return 0;
		}

		*(uint64_t*)((uint8_t*)memory_allocation_shellcode0 + 2) = (uint64_t)VirtualAlloc;
		*(uint64_t*)((uint8_t*)memory_allocation_shellcode0 + 12) = (uint64_t)shellcode_ptrs[1];

		*(uint64_t*)((uint8_t*)memory_allocation_shellcode1 + 5) = (uint64_t)shellcode_ptrs[2];

		*(uint64_t*)((uint8_t*)memory_allocation_shellcode2 + 2) = (uint64_t)size;
		*(uint64_t*)((uint8_t*)memory_allocation_shellcode2 + 12) = (uint64_t)shellcode_ptrs[3];


		*(uint64_t*)((uint8_t*)memory_allocation_shellcode3 + 9) = (uint64_t)shellcode_ptrs[4];
		
		*(uint64_t*)((uint8_t*)memory_allocation_shellcode4 + 9) = (uint64_t)shellcode_ptrs[5];

		*(uint64_t*)((uint8_t*)memory_allocation_shellcode5 + 12) = (uint64_t)shellcode_ptrs[6];

		*(uint64_t*)((uint8_t*)memory_allocation_shellcode6 + 2) = (uint64_t)data_code_cave.data();

		char zero_buff[sizeof(memory_allocation_struct)];
		char orig_data_bytes[sizeof(memory_allocation_struct)];
		memset(zero_buff, 0, sizeof(sizeof(memory_allocation_struct)));
		memset(orig_data_bytes, 0, sizeof(sizeof(memory_allocation_struct)));

		g_proc->trigger_cow_in_target(data_code_cave[0]);

		// Data codecave
		if (!g_proc->read_array(orig_data_bytes, data_code_cave[0], sizeof(memory_allocation_struct))) {
			log("Failed backup orig  data shellcode bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		if (!g_proc->write(data_code_cave[0], &zero_buff, sizeof(zero_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		/*
			Shellcode codecaves
		*/
		// Backup
		char orig_shellcode0_buff[sizeof(memory_allocation_shellcode0)];
		char orig_shellcode1_buff[sizeof(memory_allocation_shellcode1)];
		char orig_shellcode2_buff[sizeof(memory_allocation_shellcode2)];
		char orig_shellcode3_buff[sizeof(memory_allocation_shellcode3)];
		char orig_shellcode4_buff[sizeof(memory_allocation_shellcode4)];
		char orig_shellcode5_buff[sizeof(memory_allocation_shellcode5)];
		char orig_shellcode6_buff[sizeof(memory_allocation_shellcode6)];
		if (!g_proc->read_array(orig_shellcode0_buff, shellcode_ptrs[0], sizeof(orig_shellcode0_buff))) {
			log("Failed backup orig orig_shellcode0_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->read_array(orig_shellcode1_buff, shellcode_ptrs[1], sizeof(orig_shellcode1_buff))) {
			log("Failed backup orig orig_shellcode1_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->read_array(orig_shellcode2_buff, shellcode_ptrs[2], sizeof(orig_shellcode2_buff))) {
			log("Failed backup orig orig_shellcode2_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->read_array(orig_shellcode3_buff, shellcode_ptrs[3], sizeof(orig_shellcode3_buff))) {
			log("Failed backup orig orig_shellcode3_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->read_array(orig_shellcode4_buff, shellcode_ptrs[4], sizeof(orig_shellcode4_buff))) {
			log("Failed backup orig orig_shellcode4_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->read_array(orig_shellcode5_buff, shellcode_ptrs[5], sizeof(orig_shellcode5_buff))) {
			log("Failed backup orig orig_shellcode5_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->read_array(orig_shellcode6_buff, shellcode_ptrs[6], sizeof(orig_shellcode6_buff))) {
			log("Failed backup orig orig_shellcode5_buff bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		// Overwrite
		if (!g_proc->write(shellcode_ptrs[0], memory_allocation_shellcode0, sizeof(memory_allocation_shellcode0))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[1], memory_allocation_shellcode1, sizeof(memory_allocation_shellcode1))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[2], memory_allocation_shellcode2, sizeof(memory_allocation_shellcode2))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[3], memory_allocation_shellcode3, sizeof(memory_allocation_shellcode3))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[4], memory_allocation_shellcode4, sizeof(memory_allocation_shellcode4))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[5], memory_allocation_shellcode5, sizeof(memory_allocation_shellcode5))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[6], memory_allocation_shellcode6, sizeof(memory_allocation_shellcode6))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		char jump_to_shellcode[] = {
				0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,       // mov rax, gs:[0x30]
				0x8B, 0x40, 0x40,                                           // mov eax,[rax+0x40] ; pid
				0x3D, 0xDD, 0xCC, 0xAB, 0x0A,                               // cmp eax, target_pid
				0x75, 0x0C,                                                 // jne ret_label

				// Jump to my handler
				0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // mov rax, imm64 (address of my asm handler)
				0xFF, 0xE0,                                                 // jmp rax

				// All processes that don't have pid == target_pid (ret_label)
				0xC3                                                        // ret
		};
		char orig_sleep_bytes[sizeof(jump_to_shellcode)];

		*(uint64_t*)((uint8_t*)jump_to_shellcode + 21) = (uint64_t)shellcode_ptrs[0];
		*(uint32_t*)((uint8_t*)jump_to_shellcode + 13) = (uint32_t)g_proc->get_target_pid();

		/*
			Change the primary hook
		*/
		// Safe orig bytes
		if (!g_proc->read_array(orig_sleep_bytes, Sleep, sizeof(orig_sleep_bytes))) {
			log("Failed backup orig sleep bytes");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		// Hook Sleep
		if (!g_proc->write(Sleep, jump_to_shellcode, sizeof(jump_to_shellcode))) {
			log("Failed to hook Sleep to gain execution");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		/*
			Wait for memory to be allocated
		*/
		memory_allocation_struct allocation_data = { 0 };
		while (!allocation_data.result) {
			allocation_data = g_proc->read<memory_allocation_struct>(data_code_cave.data());
		}

		// Unhook Sleep
		if (!g_proc->write(Sleep, &orig_sleep_bytes, sizeof(orig_sleep_bytes))) {
			log("Failed to hook Sleep to gain execution");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		// Restore the shellcode codecave
		if (!g_proc->write(shellcode_ptrs[0], orig_shellcode0_buff, sizeof(orig_shellcode0_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[1], orig_shellcode1_buff, sizeof(orig_shellcode1_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[2], orig_shellcode2_buff, sizeof(orig_shellcode2_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[3], orig_shellcode3_buff, sizeof(orig_shellcode3_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[4], orig_shellcode4_buff, sizeof(orig_shellcode4_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[5], orig_shellcode5_buff, sizeof(orig_shellcode5_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}
		if (!g_proc->write(shellcode_ptrs[6], orig_shellcode6_buff, sizeof(orig_shellcode6_buff))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		// Restore the data codecave
		if (!g_proc->write(data_code_cave.data(), orig_data_bytes, sizeof(orig_data_bytes))) {
			log("Failed to clear data shellcode buffer");
			g_proc->revert_cow_trigger_in_target(data_code_cave[0]);
			return 0;
		}

		g_proc->revert_cow_trigger_in_target(data_code_cave[0]);

		log("Successfully allocated memory at %p in remote process", allocation_data.result);

		return allocation_data.result;
	}

	inline bool inject_dll(std::string_view dll_path) {
		if (!g_proc) {
			log("First init a process to inject a dll");
			return false;
		}

		byte* raw_dll = pe::load_raw_dll(dll_path.data());
		IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)raw_dll;
		IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((u_char*)raw_dll + dos_header->e_lfanew);

		if (!pe::is_valid_image(dos_header, nt_headers)) {
			pe::free_raw_dll(raw_dll);
			log("Invalid image");
			return false;
		}

		// Allocate memory via an IAT hook on Sleep
		void* remote_dll_base = allocate_memory_in_remote_process(nt_headers->OptionalHeader.SizeOfImage + 0x1000);
		if (!remote_dll_base) {
			log("Failed to allocate memory in remote process");
			pe::free_raw_dll(raw_dll);
			return false;
		}

		if (!pe::relocate_image(remote_dll_base, raw_dll, nt_headers)) {
			log("Failed to relocate image");
			pe::free_raw_dll(raw_dll);
			return false;
		}

		if (!pe::resolve_imports(raw_dll, nt_headers)) {
			log("Failed to resolve imports");
			pe::free_raw_dll(raw_dll);
			return false;
		}

		if (!pe::copy_headers(remote_dll_base, raw_dll, nt_headers)) {
			pe::free_raw_dll(raw_dll);
			return false;
		}

		if (!pe::copy_sections(remote_dll_base, raw_dll, nt_headers)) {
			pe::free_raw_dll(raw_dll);
			return false;
		}

		if (!pe::load_shellcode(remote_dll_base, nt_headers)) {
			pe::free_raw_dll(raw_dll);
			return false;
		}

		if (!pe::invoke_dllmain_shellcode(remote_dll_base, g_proc->get_target_pid(), nt_headers)) {
			pe::free_raw_dll(raw_dll);
			return false;
		}

		log_new_line("");
		log("Dll loaded successfully");
		return true;
	}
};