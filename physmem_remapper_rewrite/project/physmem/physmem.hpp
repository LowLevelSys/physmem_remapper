#include "../project_includes.hpp"
#include "physmem_structs.hpp"
#include "page_table_helpers.hpp"

namespace physmem {
	// Initialization functions
	project_status init_physmem(void);


	// Exposed API's
	project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address);
	project_status copy_physical_memory(uint64_t source_physical, uint64_t destination_physical, uint64_t size);
	project_status copy_virtual_memory(void* source, void* destination, uint64_t size, uint64_t source_cr3, uint64_t destination_cr3);

	// Exposed tests
	project_status stress_test_memory_copy(void);
}