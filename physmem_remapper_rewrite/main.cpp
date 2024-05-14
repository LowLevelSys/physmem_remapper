#include "includes.hpp"

// Project includes
#include "project/project_api.hpp"

NTSTATUS driver_entry(uint64_t driver_base, uint64_t driver_size) {
	project_log_success("Driver loaded at %p with size %p", driver_base, driver_size);

	project_status status = physmem::init_physmem();
	if (status != status_success){
		project_log_error("Failed to init physmem with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

    status = interrupts::init_interrupts(driver_base, driver_size);
	if (status != status_success) {
		project_log_error("Failed to init interrupts with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = physmem::stress_test_memory_copy();
	if (status != status_success) {
		project_log_error("Failed to stress test memory copy with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	project_log_success("Loading process finished");

	return STATUS_SUCCESS;
}