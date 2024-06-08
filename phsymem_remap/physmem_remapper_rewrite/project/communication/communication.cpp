#include "communication.hpp"
#include "shellcode.hpp"

#include "../project_api.hpp"
#include "../project_utility.hpp"

// Declaration of imports
extern "C" NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS PROCESS, PKAPC_STATE ApcState);
extern "C" NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

namespace communication {
    /*
        Global variables
    */
    void** data_ptr_address = 0;
    void* orig_data_ptr_value = 0;

    // Shellcode ptrs
    void* enter_constructed_space_executed = 0;
    void* enter_constructed_space_shown = 0;
    extern "C" void* exit_constructed_space = 0;

    /*
        Util
    */
    void log_data_ptr_info(void) {
        project_log_info("Data ptr value stored at: %p", data_ptr_address);
        project_log_info("Orig data ptr value: %p", orig_data_ptr_value);
        project_log_info("Exchanged data ptr value: %p", asm_handler);
    }

    /*
        Initialization functions
    */

    project_status init_data_ptr_data(void) {
        project_status status = status_success;
        void* win32k_base = 0;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };

        const char* patterns[3] = { "\x48\x83\xEC\x28\x48\x8B\x05\x99\x02", "\x48\x83\xEC\x28\x48\x8B\x05\x59\x02", "\x48\x83\xEC\x28\x48\x8B\x05\xF5\x9C" };
        uint64_t function = 0;

        int* displacement_ptr = 0;
        uint64_t target_address = 0;
        uint64_t orig_data_ptr = 0;

        status = utility::get_driver_module_base(L"win32k.sys", win32k_base);
        if (status != status_success) {
            project_log_error("Failed to get win32k.sys base address");
            goto cleanup;
        }

        status = utility::get_eprocess("winlogon.exe", winlogon_eproc);
        if (status != status_success) {
            project_log_error("Failed to get winlogon.exe eproc");
            goto cleanup;
        }

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

        // NtUserGetCPD
        // 48 83 EC 28 48 8B 05 99/59 02
        for (const auto& pattern : patterns) {
            function = utility::search_pattern_in_section(win32k_base, ".text", pattern, 9, 0x0);
            if (function)
                break;
        }

        if (!function) {
            status = status_failure;
            project_log_error("Failed to find NtUserGetCPD; You are maybe running the wrong winver");
            KeUnstackDetachProcess(&apc);
            goto cleanup;
        }

        displacement_ptr = (int*)(function + 7);
        target_address = function + 7 + 4 + *displacement_ptr;
        if (!target_address) {
            project_log_error("Failed to find data ptr address");
            KeUnstackDetachProcess(&apc);
            status = status_failure;
            goto cleanup;
        }

        orig_data_ptr = *(uint64_t*)target_address;

        KeUnstackDetachProcess(&apc);

        data_ptr_address = (void**)target_address;
        orig_data_ptr_value = (void*)orig_data_ptr;

    cleanup:
        return status;
    }

    project_status ensure_driver_mapping(void* driver_base, uint64_t driver_size) {
        project_status status = status_success;

        // First unset the global flag of the driver pages to avoid it staying in the tlb
        status = physmem::unset_global_flag_for_range(driver_base, driver_size, physmem::get_system_cr3().flags);
        if (status != status_success) {
            project_log_error("Failed to unset the global flag on one of the drivers pages");
            return status;
        }

        // Then ensure the driver mapping in our cr3
        status = physmem::ensure_memory_mapping_for_range(driver_base, driver_size, physmem::get_system_cr3().flags);
        if (status != status_success) {
            project_log_error("Failed to ensure driver mapping");
            project_log_error("If you remove it from physical memory now and call it, you WILL bsod");
            return status;
        }

        _cli();
        uint64_t old_cr3 = __readcr3();
        __writecr3(physmem::get_constructed_cr3().flags);

        status = physmem::overwrite_virtual_address_mapping(enter_constructed_space_shown, enter_constructed_space_executed,
                                                            physmem::get_system_cr3().flags, physmem::get_system_cr3().flags);
        if (status != status_success) {
            __writecr3(old_cr3);
            _sti();
            project_log_error("Failed to ensure driver mapping");
            return status;
        }

        __writecr3(old_cr3);
        _sti();

        return status;
    }

    project_status init_data_ptr_hook(void) {
        project_status status = status_success;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };

        status = utility::is_data_ptr_valid((uint64_t)orig_data_ptr_value);
        if (status != status_success) {
            project_log_error("Data ptr at: %p already hooked", data_ptr_address);
            return status;
        }

        status = utility::get_eprocess("winlogon.exe", winlogon_eproc);
        if (status != status_success) {
            project_log_error("Failed to get winlogon.exe EPROCESS");
            goto cleanup;
        }

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

        if (!InterlockedExchangePointer((void**)data_ptr_address, (void*)enter_constructed_space_shown)) {
            KeUnstackDetachProcess(&apc);
            project_log_error("Failed to exchange ptr at: %p", data_ptr_address);
            status = status_failure;
            goto cleanup;
        }

        KeUnstackDetachProcess(&apc);

    cleanup:

        return status;
    }

    project_status init_communication(void* driver_base, uint64_t driver_size) {
        if (!interrupts::is_initialized() || !stack_manager::is_initialized() || !physmem::is_initialized())
            return status_not_initialized;

        project_status status = status_success;

        status = init_data_ptr_data();
        if (status != status_success)
            goto cleanup;

        status = shellcode::construct_shellcodes(enter_constructed_space_executed, enter_constructed_space_shown, 
            exit_constructed_space,
            interrupts::get_constructed_idt_ptr(), orig_data_ptr_value, 
            asm_handler, physmem::get_constructed_cr3().flags);

        if (status != status_success)
            goto cleanup;

        status = ensure_driver_mapping(driver_base, driver_size);
        if (status != status_success)
            goto cleanup;

        shellcode::log_shellcode_addresses();

        status = init_data_ptr_hook();
        if (status != status_success)
            goto cleanup;

    cleanup:
        return status;
    }
};