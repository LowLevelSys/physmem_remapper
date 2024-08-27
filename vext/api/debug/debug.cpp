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
			log("Failed pinging the driver");
			return;
		}

		log("Sucessfully tested driver");
		getchar();
	}
};