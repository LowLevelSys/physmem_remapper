#include "driver/driver_um_lib.hpp"
#include "proc/process.hpp"

int main(void) {
	std::string target_name = { 0 };
	std::string dll_path = { 0 };
	log("Enter the target name: ");
	getline(std::cin, target_name);

	log("Enter the DLL path: ");
	getline(std::cin, dll_path);

	if (target_name.empty()) {
		log("No process specified; Not testing");
		getchar();
		return -1;
	}

	if (!dll_path.ends_with(".dll")) {
		log("Nothing other then dlls injectable");
		getchar();
		return -1;
	}

	g_proc = process_t::get_inst(target_name.c_str());
	if (!g_proc) {
		log("Failed to init process instance for process %s", target_name.c_str());
		getchar();
		return -1;
	}

	if(!inject::inject_dll(dll_path)) {
		log("Failed to inject dll %s into process %s", dll_path.c_str(), target_name.c_str());
		getchar();
		return -1;
	}

	log("Sucessfully injected dll %s into process %s", dll_path.c_str(), target_name.c_str());

	getchar();
	return 0;
}