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
	// notepad.exe
	if (!g_proc->init_process("Overwatch.exe")) {
		log("Failed to attach to process");
		getchar();
		return -1;
	}

	uint64_t ow_base = g_proc->get_module_base("Overwatch.exe");
	if (!ow_base) {
		log("Failed to get Ow base");
		getchar();
		return -1;
	}

	uint64_t iteration = 0;
	while (true) {
		float current_fov = 0.f;

		current_fov = g_proc->read<float>((void*)(ow_base + 0x395edb8));

		log("[%p] Current fov %.2f", iteration, current_fov);

		//std::this_thread::sleep_for(std::chrono::milliseconds(1));
		iteration++;
	}

	return 0;
}