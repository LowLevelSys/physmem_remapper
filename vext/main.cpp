#include "api/driver/driver_um_lib.hpp"
#include "api/proc/process.hpp"
#include "api/dumper/driver_dumper.hpp"
#include "api/debug/debug.hpp"

void proc_test(void) {
	// FortniteClient-Win64-Shipping.exe
	// FortniteClient-Win64-Shipping_EAC_EOS.exe
	// VALORANT-Win64-Shipping.exe
	// r5apex.exe
	// DeadByDaylight-Win64-Shipping.exe
	// notepad.exe
	std::string proc = "notepad.exe";
	if (!process::attach_to_proc(proc)) {
		return;
	}

	process::testing::speed_test();
	process::log_modules();
	physmem::flush_logs();

	return;
}

int main(void) {
	debug::test_driver();
	getchar();
	return 0;
}