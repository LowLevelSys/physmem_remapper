#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

const std::string target_proc = "notepad.exe";
const std::string target_func_string = "MessageBoxA";
void* target_func = MessageBoxA;

int main(void) {
	g_proc = process_t::get_inst(target_proc);
	if (!g_proc) {
		log("Failed to init process instance");
		getchar();
		return -1;
	}

	if (!g_proc->trigger_cow_in_target(target_func)) {
		log("Failed to trigger cow on %s", target_func_string);
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
	g_proc->revert_cow_trigger_in_target(target_func);


	uint64_t mod_base = g_proc->get_module_base(target_proc);
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