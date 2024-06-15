#include "dbd/dbd.hpp"

int main(void) {

	if (!dbd::init_cheat()) {
		log("Failed to init cheat");
		getchar();
		return -1;
	}

	return 0;
}