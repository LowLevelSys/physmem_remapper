#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	g_proc = process_t::get_inst();

	if (!g_proc) {
		log("Failed to init process instance");
		getchar();
		return -1;
	}

	// VALORANT-Win64-Shipping.exe
	// Notepad.exe
	if (!g_proc->init_process("Notepad.exe")) {
		log("Failed to attach to process");
		getchar();
		return -1;
	}

	uint64_t ow_base = g_proc->get_module_base("Notepad.exe");
	if (!ow_base) {
		log("Failed to get Ow base");
		getchar();
		return -1;
	}

	std::this_thread::sleep_for(std::chrono::seconds(1));

	uint64_t iteration = 0;
	uint64_t result = 0;

	for (;; iteration++) {
		//bool apc_result = g_proc->remove_apc();
		//log("Apc Remove: %s", apc_result ? "Success" : "Failed");

		result = g_proc->read<uint64_t>((void*)(ow_base));
		log("[%d] result %llx", iteration, result);

		//apc_result = g_proc->restore_apc();
		//log("Apc Restore: %s", apc_result ? "Success" : "Failed");
	}

	return 0;
}