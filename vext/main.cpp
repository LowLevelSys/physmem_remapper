#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

const std::string target_proc = "notepad.exe";
const std::string target_func_string = "MessageBoxA";
void* target_func = MessageBoxA;
size_t page_size = 0x1000;

int main(void) {
	g_proc = process_t::get_inst(target_proc);
	if (!g_proc) {
		log("Failed to init process instance");
		getchar();
		return -1;
	}

	if (!g_proc->trigger_cow_in_target(target_func)) {
		log("Failed to trigger cow on %s", target_func_string.c_str());
		getchar();
		return -1;
	}

	log("COW Triggered");
	getchar();

	if (!g_proc->find_and_copy_cow_page(target_func, page_size)) {
		log("Failed to find and copy COW page");
		getchar();
		g_proc->revert_cow_trigger_in_target(target_func);
		// revert before returning to prevent BSOD
		getchar();
		return -1;
	}

	g_proc->revert_cow_trigger_in_target(target_func);
	log("COW change reverted successfully");

	///////////////////////////////////////////////////////////

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