#include "communication.hpp"
#include "shellcode.hpp"

#include "../project_api.hpp"
#include "../project_utility.hpp"

// Declaration of imports
extern "C" NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS PROCESS, PKAPC_STATE ApcState);
extern "C" NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

extern "C" void asm_handler(void);

extern "C" void test_function_c(void);

namespace communication {
    /*
        Global variables
    */
    void** data_ptr_address = 0;
    void* orig_data_ptr_value = 0;

    // Shellcode ptrs
    extern "C" void* enter_constructed_space = 0;
    extern "C" void* exit_constructed_space = 0;
    extern "C" void* nmi_shellcode = 0;

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
        uint64_t pattern = 0;

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
        pattern = utility::search_pattern_in_section(win32k_base, ".text", "\x48\x83\xEC\x28\x48\x8B\x05\x99\x02", 9, 0x0);

        if (!pattern) {
            pattern = utility::search_pattern_in_section(win32k_base, ".text", "\x48\x83\xEC\x28\x48\x8B\x05\x59\x02", 9, 0x0);

            if (!pattern) {
                status = status_failure;
                project_log_error("Failed to find NtUserGetCPD; You are maybe running the wrong winver");
                KeUnstackDetachProcess(&apc);
                goto cleanup;
            }
        }

        displacement_ptr = (int*)(pattern + 7);
        target_address = pattern + 7 + 4 + *displacement_ptr;
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

        if (!InterlockedExchangePointer((void**)data_ptr_address, (void*)enter_constructed_space)) {
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
        void* my_stack_base = 0;
        
        status = init_data_ptr_data();
        if (status != status_success)
            goto cleanup;

        status = stack_manager::get_stack_base(my_stack_base);
        if (status != status_success)
            goto cleanup;

        status = shellcode::construct_shellcodes(enter_constructed_space, exit_constructed_space, nmi_shellcode,
            interrupts::get_windows_nmi_handler(), interrupts::get_constructed_idt_ptr(),
            orig_data_ptr_value, asm_handler, my_stack_base, physmem::get_constructed_cr3().flags);
        if (status != status_success)
            goto cleanup;

        shellcode::log_shellcode_addresses();

        status = ensure_driver_mapping(driver_base, driver_size);
        if (status != status_success)
            goto cleanup;

        status = init_data_ptr_hook();
        if (status != status_success)
            goto cleanup;

    cleanup:
        return status;
    }
};