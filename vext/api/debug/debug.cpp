#include "debug.hpp"

namespace debug {
	// Is only part of the initialization, only the part that does not actually call the driver
	bool skeleton_init_lib(void) {
		// For some reason user32.dll has to also be loaded for calls to NtUser functions to work?
		if (!LoadLibraryW(L"user32.dll")) {
			log("Failed to load user32.dll");
			return false;
		}

		HMODULE win32u = LoadLibraryW(L"win32u.dll");
		if (!win32u) {
			log("Failed to get win32u.dll handle");
			return false;
		}

		uint64_t handler_address = (uint64_t)GetProcAddress(win32u, "NtUserGetCPD");

		NtUserGetCPD = (NtUserGetCPD_type)handler_address;
		physmem::inited = true;

		return true;
	}

	bool test_ping(void) {
		return physmem::ping_driver();
	}

	bool test_hiding(void) {
		return physmem::hide_driver();
	}

	bool test_getting_cr3(void) {
		uint64_t curr_cr3 = physmem::get_cr3(GetCurrentProcessId());
		if (!curr_cr3)
			return false;

		return true;
	}

	bool test_memory_copying(void) {
		uint64_t curr_cr3 = physmem::get_cr3(GetCurrentProcessId());
		if (!curr_cr3)
			return true;

		uint64_t a = 0;
		uint64_t b = 1;

		if (!physmem::copy_virtual_memory(curr_cr3, curr_cr3, &b, &a, sizeof(uint64_t)))
			return false;

		return a == b;
	}

	bool test_unloading() {
		return physmem::unload_driver();
	}

	void test_driver(void) {
		log("Press enter to continue");
		log("Loading lib...");
		getchar();
		if (!skeleton_init_lib()) {
			log("Failed loading the remapper lib");
			return;
		}

		log("Press enter to continue");
		log("Pinging driver...");
		getchar();
		if (!test_ping()) {
			log("Failed pinging the driver");
			return;
		}

		log("Press enter to continue");
		log("Hiding driver...");
		getchar();
		if (!test_hiding()) {
			log("Failed hiding the driver");
			return;
		}

		log("Press enter to continue");
		log("Cr3 getting...");
		getchar();
		if (!test_getting_cr3()) {
			log("Failed getting cr3");
			return;
		}

		log("Press enter to continue");
		log("Memory copying...");
		getchar();
		if (!test_memory_copying()) {
			log("Failed memory copying");
			return;
		}

		log("Press enter to continue");
		log("Unloading driver...");
		getchar();
		if (!test_unloading()) {
			log("Failed unloading the driver");
			return;
		}

		log("Sucessfully tested driver");
	}
};