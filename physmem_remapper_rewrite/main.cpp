#include "includes.hpp"
#include "project/project_api.hpp"

project_status call_stress_tests(void) {
	project_status status = status_success;

	status = physmem::stress_test_memory_copy();
	if (status != status_success) {
		project_log_error("Failed to stress test memory copying with status %d", status);
		return status;
	}

	status = physmem::stress_test_memory_remapping();
	if (status != status_success) {
		project_log_error("Failed to stress test memory remapping with status %d", status);
		return status;
	}

	return status;
}

NTSTATUS driver_entry() {
	project_log_success("Driver loaded!");

	project_status status = status_success;

	status = physmem::init_physmem();
	if (status != status_success){
		project_log_error("Failed to init physmem with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

    status = interrupts::init_interrupts();
	if (status != status_success) {
		project_log_error("Failed to init interrupts with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = stack_manager::init_stack_manager();
	if (status != status_success) {
		project_log_error("Failed to init stack manager with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = communication::init_communication();
	if (status != status_success) {
		project_log_error("Failed to init communication with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	/* 
	Stress tests take a while to execute, so I would advocate against executing them
	but for testing purposes you can of course call them

	status = call_stress_tests();
	if (status != status_success)
		return STATUS_UNSUCCESSFUL;
	*/

	project_log_success("Loading process finished sucessfully");

	return STATUS_SUCCESS;
}