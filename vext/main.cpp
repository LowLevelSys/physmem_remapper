#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	g_proc = process_t::get_inst("notepad.exe");
	if (!g_proc) {
		log("Failed to init process instance");
		getchar();
		return -1;
	}

	uint64_t mod_base = g_proc->get_module_base("notepad.exe");
	if (!mod_base) {
		log("Failed to get notepad base");
		getchar();
		return -1;
	}

	while (true) {
		g_proc->speed_test();
		Sleep(1000);
	}

	getchar();

	return 0;
}