#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	g_proc = process_t::get_inst("notepad.exe");
	if (!g_proc) {
		log("Failed to init process instance");
		getchar();
		return -1;
	}

	uint64_t ow_base = g_proc->get_module_base("notepad.exe");
	if (!ow_base) {
		log("Failed to get Ow base");
		getchar();
		return -1;
	}

	uint64_t iteration = 0;
	uint64_t result = 0;

	for (;; iteration++) {
		result = g_proc->read<uint64_t>((void*)(ow_base));
		log("[%d] result %llx", iteration, result);
	}

	return 0;
}