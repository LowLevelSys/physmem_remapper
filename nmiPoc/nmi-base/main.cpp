#include "idt/idt.hpp"

void no_api_sleep(unsigned int milliseconds) {
    unsigned long long start, end, elapsed, freq;

    freq = 2600000000ULL;

    // Calculate the number of cycles needed to wait
    unsigned long long waitCycles = (freq / 1000) * milliseconds;

    start = __rdtsc();
    end = start + waitCycles;

    do {
        elapsed = __rdtsc();
    } while (elapsed < end);
}

void test(void) {
    int iter = 50;

    KAFFINITY orig_affinity = KeSetSystemAffinityThreadEx(1ull << 3);

    while (iter >= 0) {
        idt_ptr_t curr_idt;

        __sidt(&curr_idt);
        __lidt(&my_idt_ptr);

        no_api_sleep(100);

        __lidt(&curr_idt);

        iter--;
    }

    KeRevertToUserAffinityThreadEx(orig_affinity);

    dbg_log("Logging NMI info: ");
    for (uint64_t i = 0; i < caught_counter; i++) {
        nmi_interupt_info_t& curr_info = infos[i];

        dbg_log("--- Called NMI handler on core %d---", curr_info.core_number);
        dbg_log("Rip %p", curr_info.rip);
        dbg_log("Rsp %p", curr_info.rsp);
        dbg_log("Cr3 %p", curr_info.cr3);
        dbg_log_no_prefix("\n");

        dbg_log("--- Stack info ---");
        dbg_log("Stack base: %p", curr_info.stack_base);
        dbg_log("Stack limit: %p", curr_info.stack_limit);
        dbg_log("Stack size: %p", curr_info.stack_base - curr_info.stack_limit);
        dbg_log_no_prefix("\n");
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS driver_entry(uint64_t driver_base, uint64_t driver_size) {

	if (!init_seh(driver_base, driver_size)) {
		dbg_log("Failed to init seh");
		return STATUS_UNSUCCESSFUL;
	}

    HANDLE thread;
    CLIENT_ID thread_id;

    PsCreateSystemThread(&thread, STANDARD_RIGHTS_ALL, NULL, NULL, &thread_id, (PKSTART_ROUTINE)test, (void*)0);
    ZwClose(thread);

	return STATUS_SUCCESS;
}