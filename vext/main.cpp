#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	g_proc = process_t::get_inst("notepad.exe");
	if (!g_proc) {
		log("Failed to init process instance");
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