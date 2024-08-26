#include "project/project_api.hpp"

NTSTATUS driver_entry(void* driver_base, uint64_t driver_size) {
	project_log_success("Driver loaded at %p with size %p", driver_base, driver_size);

	if (!driver_base || !driver_size) {
		project_log_success("Wrong usage: You have to pass the allocation base and the allocation size of the driver pool to the driver_entry!");
		return STATUS_UNSUCCESSFUL;
	}

	g_driver_base = driver_base;
	g_driver_size = driver_size;

	project_status status = status_success;
	status = interrupts::init_interrupts();
	if (status != status_success) {
		project_log_error("Failed to init interrupts with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = physmem::init_physmem();
	if (status != status_success) {
		project_log_error("Failed to init physmem with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = cr3_decryption::init_eac_cr3_decryption();
	if (status != status_success) {
		project_log_error("Failed to init cr3 decryption with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = logging::init_root_logger();
	if (status != status_success) {
		project_log_error("Failed to init logger with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = communication::init_communication(driver_base, driver_size);
	if (status != status_success) {
		project_log_error("Failed to init communication with status %d", status);
		return STATUS_UNSUCCESSFUL;
	}

	project_log_success("Loading process finished sucessfully");

	return STATUS_SUCCESS;
}