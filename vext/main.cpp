#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	g_proc = process_t::get_inst("notepad.exe");
	if (!g_proc) {
		log("Failed to init process instance");
		getchar();
		return -1;
	}

	if (!g_proc->trigger_cow_in_target(MessageBoxA)) {
		log("Failed to trigger cow on MessageBoxA");
		getchar();
		return -1;
	}

	/*
		Don't close notepad before the change is reverted or you will bsod
		Also if you close this process before the target the cow change will go to shit	
	*/
	log("Cow triggered");
	getchar();

	// If you do not revert the trigger it WILL bsod cause of memory management when the process closes
	g_proc->revert_cow_trigger_in_target(MessageBoxA);

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