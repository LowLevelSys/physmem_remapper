#include "communication.hpp"

#include "../project_api.hpp"
#include "../project_utility.hpp"

// C implementation of our handler

/*
    Our main handler that handles communication with um
    a) It assumes that the call to it is valid; Validity is checked for in shell code via rdx
    hwnd: ptr to cmd
    flags: non valid (is used as a validation key in the shellcode)
    dw_data: non valid
*/
extern "C" __int64 __fastcall handler(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data) {
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(dw_data);
    UNREFERENCED_PARAMETER(hwnd);

    project_log_info("Hello from inside my data ptr hook");

    return 0;
}