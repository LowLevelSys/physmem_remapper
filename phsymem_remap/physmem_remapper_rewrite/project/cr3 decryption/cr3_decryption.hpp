#pragma once
#include "../project_api.hpp"
#include "../project_utility.hpp"

#pragma warning(push)
#pragma warning(disable:4201)
struct _MMPFN {
	uintptr_t flags;
	uintptr_t pte_address;
	uintptr_t Unused_1;
	uintptr_t Unused_2;
	uintptr_t Unused_3;
	uintptr_t Unused_4;
};
static_assert(sizeof(_MMPFN) == 0x30);

constexpr size_t operator ""_MiB(size_t num) { return num << 20; }

namespace cr3_decryption {
	// Initialization
	project_status init_eac_cr3_decryption(void);

	uint64_t get_decrypted_cr3(uint64_t pid);
}