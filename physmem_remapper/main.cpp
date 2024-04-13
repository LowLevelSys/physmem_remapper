#include "physmem/physmem.hpp"
#include "../communication/comm.hpp"
#include "../idt/idt.hpp"
#include "../gdt/gdt.hpp"

/*
	For Information as to why it was a pain to implement
	please consult the Intel Sdm Volume 3: 4.10.2.4 (Global Pages)
*/

bool can_return_entry = false;

void sleep(uint64_t ms) {
	// Convert milliseconds to 100-nanosecond intervals
	// Negative value indicates a relative time
	LARGE_INTEGER interval;
	interval.QuadPart = -((LONGLONG)ms * 10 * 1000);

	// Set the thread to an alertable state to delay its execution
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

void init() {

	// Example usage
	physmem* instance = physmem::get_physmem_instance();

	// First see whether initialization worked
	if (!instance) {
		dbg_log_main("Failed to setup the physmem instance");
		return;
	}

	if (!init_idt()) {
		dbg_log_main("Failed to successfully init my idt");
		return;
	}

	if (!init_gdt()) {
		dbg_log_main("Failed to successfully init my gdt");
		return;
	}

	// Define the physmem_test if you really want the test to be executed
	if (!physmem_experiment()) {
		dbg_log_main("Failed to successfully execute the physmem experiment");
		return;
	}

	// Replace a .data ptr with a ptr to a write cr3 gadget that then calls our handler
	if (!init_communication()) {
		dbg_log_main("Failed to init communication");
		return;
	}

	dbg_log_main("Driver initialized successfully!");

	// Now indicate us being finished
	can_return_entry = true;
}

// Just a basic driver entry
NTSTATUS driver_entry(uint64_t base, uint64_t size) {

	dbg_log_entry("Driver at va %p - %p in system page tables", base, base + size);

	driver_base = base;
	driver_size = size;

	HANDLE thread;
	CLIENT_ID thread_id;

	PsCreateSystemThread(&thread, STANDARD_RIGHTS_ALL, NULL, NULL, &thread_id, (PKSTART_ROUTINE)init, (void*)0);
	ZwClose(thread);

	while (!can_return_entry)
		sleep(10);

	// Just to ensure the thread above is finished
	sleep(10);

	return STATUS_SUCCESS;
}