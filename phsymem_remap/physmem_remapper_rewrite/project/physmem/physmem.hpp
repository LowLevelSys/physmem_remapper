#include "../project_includes.hpp"
#include "../windows_structs.hpp"

#include "physmem_structs.hpp"
#include "page_table_helpers.hpp"

namespace physmem {
	// Initialization functions
	project_status init_physmem(void);

	// Exposed API's that are designed to be used universal
	bool is_initialized(void);
	cr3 get_constructed_cr3(void);
	cr3 get_system_cr3(void);
	void free_mem_copying_pte_table(void);

	// Exposed API's designed to be called during normal execution
	project_status copy_physical_memory(uint64_t destination_physical, uint64_t source_physical, uint64_t size);
	project_status copy_virtual_memory(void* destination, void* source, uint64_t size, uint64_t destination_cr3, uint64_t source_cr3);

	project_status copy_memory_to_constructed_cr3(void* destination, void* source, uint64_t size, uint64_t source_cr3);
	project_status copy_memory_from_constructed_cr3(void* destination, void* source, uint64_t size, uint64_t destination_cr3);

	project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address);
	project_status get_pte_entry(void* virtual_address, uint64_t mem_cr3_u64, pte_64*& mem_pte);
	void safely_unmap_4kb_page(void* mapped_page);

	// Exposed API's designed to be called in initialization
	project_status overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64);
	project_status restore_virtual_address_mapping(void* target_address, uint64_t mem_cr3_u64);

	project_status ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3);

	project_status unset_global_flag_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64);
};