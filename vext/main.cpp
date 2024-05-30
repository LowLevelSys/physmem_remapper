#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	g_proc = process_t::get_inst();

	if (!g_proc) {
		log("Failed to init process instance");
		return -1;
	}

	// VALORANT-Win64-Shipping.exe
	// notepad.exe
	if (!g_proc->init_process("notepad.exe")) {
		log("Failed to attach to process");
		return -1;
	}

	return 0;
}