#include "comm.hpp"

__int64 __fastcall handler(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data) {

	if (hwnd != 0x1337) {
		// First pop rax in order to not pollute any regs
		__pop_rax();

		// Write the normal cr3 back into cr3 for now
		__writecr3(physmem::get_physmem_instance()->get_kernel_cr3());

		// Then flush the global page too
		__invlpg((void*)global_new_data_ptr);

		// And return the normal function
		return orig_NtUserGetCPD(hwnd, flags, dw_data);
	}

	// First pop rax in order to not pollute any regs
	__pop_rax();

	// Write the normal cr3 back into cr3 for now
	__writecr3(physmem::get_physmem_instance()->get_kernel_cr3());

	dbg_log("Hi!");

	// And return the normal function
	return orig_NtUserGetCPD(hwnd, flags, dw_data);
}