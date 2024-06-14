#include "dbd/dbd.hpp"

int main(void) {

	if (!dbd::init_cheat()) {
		log("Failed to init cheat");
		getchar();
		return -1;
	}

	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	return 0;
}