#include "api/driver/driver_um_lib.hpp"
#include "api/proc/process.hpp"
#include "api/dumper/driver_dumper.hpp"

void proc_test(void) {
	// FortniteClient-Win64-Shipping.exe
	// FortniteClient-Win64-Shipping_EAC_EOS.exe
	// VALORANT-Win64-Shipping.exe
	// r5apex.exe
	// DeadByDaylight-Win64-Shipping.exe
	// notepad.exe
	std::string proc = "r5apex.exe";
	if (!process::attach_to_proc(proc))
		return;

	process::log_modules();

	uint8_t count = 5;
	while (count > 0) {
		process::testing::speed_test();
		Sleep(1000);
		count--;
	}

	log("Finished speed test\n");

	if (!physmem::unload_driver()) {
		log("ERROR: Failed to unload driver");
		return;
	}

	log("Unloaded driver");

	return;
}

void driver_dump_test(void) {
	std::string target_driver = "vgk.sys";
	std::filesystem::path curr_path = std::filesystem::current_path();
	if (!driver_dumper::dump_driver(target_driver, curr_path.string()))
		return;
	
}

void force_unload(void) {
	physmem::force_unload_driver();
}

int main(void) {
	//driver_dump_test();
	proc_test();

	getchar();
	return 0;
}