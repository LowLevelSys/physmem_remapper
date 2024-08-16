#pragma once
#pragma warning (disable: 4003)
#include "../driver/driver_um_lib.hpp"

namespace driver_dumper {
	inline bool inited = false;

	// Owner specific data
	inline uint64_t owner_pid = 0;
	inline uint64_t owner_cr3 = 0;

	// Kernel data
	inline uint64_t kernel_cr3 = 0;

	namespace core {
		inline bool init_physmem() {
			if (!physmem::init_physmem_remapper_lib()) {
				log("Can't init process if the physmem instance is not allocated");
				return false;
			}

			if (!physmem::is_lib_inited()) {
				log("Can't init process if the physmem instance is not initialized");
				return false;
			}

			owner_pid = GetCurrentProcessId();
			if (!owner_pid) {
				log("Failed to get pid of owner process");
				return false;
			}

			owner_cr3 = physmem::get_cr3(owner_pid);
			if (!owner_cr3) {
				log("Failed to get cr3 of owner process");
				return false;
			}

			kernel_cr3 = physmem::get_cr3(4);
			if (!kernel_cr3) {
				log("Failed to get cr3 of the kernel");
				return false;
			}

			inited = true;

			return true;
		}

		struct RTL_PROCESS_MODULE_INFORMATION {
			PVOID  Section;
			PVOID  MappedBase;
			PVOID  ImageBase;
			ULONG  ImageSize;
			ULONG  Flags;
			USHORT LoadOrderIndex;
			USHORT InitOrderIdnex;
			USHORT LoadCount;
			USHORT OffsetToFileName;
			CHAR   FullPathName[0x100];
		};

		struct RTL_PROCESS_MODULES {
			ULONG                          NumberOfModules;
			RTL_PROCESS_MODULE_INFORMATION Modules[1];
		};

		// get the image base and image size of a loaded driver
		bool find_loaded_driver(char const* const name, void*& imagebase, uint32_t& imagesize) {
			using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(uint32_t SystemInformationClass,
				PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
			static auto const NtQuerySystemInformation = (NtQuerySystemInformationFn)(
				GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

			// get the size of the buffer that we need to allocate
			unsigned long length = 0;
			NtQuerySystemInformation(0x0B, nullptr, 0, &length);

			auto const info = (RTL_PROCESS_MODULES*)(new uint8_t[length + 0x200]);
			NtQuerySystemInformation(0x0B, info, length + 0x200, &length);

			for (unsigned int i = 0; i < info->NumberOfModules; ++i) {
				auto const& m = info->Modules[i];
				if (_stricmp(m.FullPathName + m.OffsetToFileName, name) != 0)
					continue;

				imagebase = m.ImageBase;
				imagesize = m.ImageSize;

				delete info;
				return true;
			}

			delete info;
			return false;
		}

		template <typename t>
		inline t read_kernel(void* src, uint64_t size = sizeof(t)) {
			t buffer{};

			if (!physmem::copy_virtual_memory(physmem::get_cr3(4), owner_cr3, src, &buffer, sizeof(t))) {
				log("Failed to copy memory from src: [%p] to dest: [%p]", (void*)src, &buffer);
				return { 0 };
			}

			return buffer;
		}
	};


	inline bool dump_driver(std::string driver_name, std::string output_path) {
		if (!core::init_physmem())
			return false;

		log("Trying to dump %s\n", driver_name.c_str());

		void* imagebase = nullptr;
		uint32_t imagesize = 0;

		if (!core::find_loaded_driver(driver_name.c_str(), imagebase, imagesize)) {
			log("Driver %s not loaded", driver_name.c_str());
			return false;
		}

		log("Found %s at %p with size %p\n", driver_name.c_str(), imagebase, imagesize);

		std::vector<char> image;
		image.resize(imagesize);

		// Copy headers
		if (!physmem::copy_virtual_memory(kernel_cr3, owner_cr3, imagebase, image.data(), 0x1000)) {
			log("Failed to copy driver headers");
			return false;
		}

		// Copy the "meat" of the driver; 
		// Cause of virtual alignment and bs the last pages might not be present -> no error check possible
		physmem::copy_virtual_memory(kernel_cr3, owner_cr3, imagebase, image.data(), imagesize);

		// Fix the headers
		IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)image.data();
		IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)((uint64_t)image.data() + dos_header->e_lfanew);
		IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(nt_header + 1);

		nt_header->OptionalHeader.ImageBase = (uintptr_t)imagebase;
		for (size_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
			std::string section_name((char*)sections[i].Name);
			sections[i].PointerToRawData = sections[i].VirtualAddress;
			sections[i].SizeOfRawData = sections[i].Misc.VirtualSize;

			if (i == nt_header->FileHeader.NumberOfSections - 1) {
				log("[%s] Va: %08x; Size %08x\n", section_name.c_str(), sections[i].PointerToRawData, sections[i].SizeOfRawData);
				continue;
			}

			log("[%s] Va: %08x; Size: %08x", section_name.c_str(), sections[i].PointerToRawData, sections[i].SizeOfRawData);
		}

		output_path.append("\\dump_" + driver_name);

		std::ofstream output_file(output_path, std::ios::binary);
		if (!output_file.is_open()) {
			log("Failed to open output file: %s", output_path.c_str());
			return false;
		}
		output_file.write((char*)image.data(), imagesize);
		output_file.close();

		log("Successfully dumped %s\n", output_path.c_str());

		return true;
	}
};