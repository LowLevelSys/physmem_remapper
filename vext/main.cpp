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
	std::string proc = "FortniteClient-Win64-Shipping.exe";
	if (!process::attach_to_proc(proc))
		return;

	process::log_modules();

	return;
}

int main(void) {
	proc_test();

	getchar();
	return 0;
}