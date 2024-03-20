#include "physmem/physmem.hpp"
#include "../communication/comm.hpp"

/*
NTSTATUS MmAllocateCopyRemove
(
	_In_ ULONG DataSize,
	_Out_ PPHYSICAL_ADDRESS PhysPtr
)
{
	LARGE_INTEGER AllocSize;
	PHYSICAL_ADDRESS MaxPhys;

	PVOID Alloc = NULL;
	MaxPhys.QuadPart = MAXLONG64;
	AllocSize.QuadPart = DataSize;
	Alloc = MmAllocateContiguousMemory(DataSize, MaxPhys);

	dbg_log("Alloc at %p", Alloc);

	if (!Alloc)
		return STATUS_FAIL_CHECK;

	*PhysPtr = MmGetPhysicalAddress(Alloc);

	dbg_log("Physmem at %p", *PhysPtr);

	MmFreeContiguousMemory(Alloc);
	return MmRemovePhysicalMemory(PhysPtr, &AllocSize);
}
*/

/*
	For Information as to why it was a pain to implement
	please consult the Intel Sdm Volume 3: 4.10.2.4 (Global Pages)
*/

void init() {
	// Example usage
	physmem* instance = physmem::get_physmem_instance();

	// First see whether initialization worked
	if (!instance) {
		dbg_log("Failed to setup the physmem instance");
		return;
	}
	
	// Define the physmem_test if you really want the test to be executed
	if (!physmem_experiment()) {
		dbg_log("Failed to successfully execute the physmem experiment");
		return;
	}

	// Replace a .data ptr with a ptr to a write cr3 gadget that then calls our handler
	if (!init_communication()) {
		dbg_log("Failed to init communication");
		return;
	}

	dbg_log("Driver initialized successfully!");
}

// Just a basic driver entry
NTSTATUS driver_entry(uint64_t base, uint64_t size) {

	driver_base = base;
	driver_size = size;

	HANDLE thread;
	CLIENT_ID thread_id;

	PsCreateSystemThread(&thread, STANDARD_RIGHTS_ALL, NULL, NULL, &thread_id, (PKSTART_ROUTINE)init, (void*)0);
	ZwClose(thread);

	return STATUS_SUCCESS;
}