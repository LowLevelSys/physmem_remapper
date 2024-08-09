#include "../project_includes.hpp"
#include "../windows_structs.hpp"

#include "physmem_structs.hpp"
#include "page_table_helpers.hpp"

namespace physmem {
	// Initialization functions
	project_status init_physmem(void);

	namespace util {
		bool is_initialized(void);
		cr3 get_constructed_cr3(void);
		cr3 get_system_cr3(void);
	};

	namespace runtime {
		project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t& remaining_bytes);

		void copy_physical_memory(uint64_t dst_physical, uint64_t src_physical, uint64_t size);
		project_status copy_virtual_memory(void* dst, void* src, uint64_t size, uint64_t dst_cr3, uint64_t src_cr3);
		project_status copy_memory_to_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t src_cr3);
		project_status copy_memory_from_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t dst_cr3);
	};

	namespace testing {
		bool memory_copy_test1(void);
	};

};