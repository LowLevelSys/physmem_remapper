#pragma once
#include "../project_includes.hpp"

typedef struct {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuidsplit_t;

typedef struct {
    union {
        struct {
            uint32_t stepping_id : 4;
            uint32_t model : 4;
            uint32_t family_id : 4;
            uint32_t processor_type : 2;
            uint32_t reserved1 : 2;
            uint32_t extended_model_id : 4;
            uint32_t extended_family_id : 8;
            uint32_t reserved2 : 4;
        };

        uint32_t flags;
    } cpuid_version_information;

    union {
        struct {
            uint32_t brand_index : 8;
            uint32_t clflush_line_size : 8;
            uint32_t max_addressable_ids : 8;
            uint32_t initial_apic_id : 8;
        };

        uint32_t flags;
    } cpuid_additional_information;

    union {
        struct {
            uint32_t streaming_simd_extensions_3 : 1;
            uint32_t pclmulqdq_instruction : 1;
            uint32_t ds_area_64bit_layout : 1;
            uint32_t monitor_mwait_instruction : 1;
            uint32_t cpl_qualified_debug_store : 1;
            uint32_t virtual_machine_extensions : 1;
            uint32_t safer_mode_extensions : 1;
            uint32_t enhanced_intel_speedstep_technology : 1;
            uint32_t thermal_monitor_2 : 1;
            uint32_t supplemental_streaming_simd_extensions_3 : 1;
            uint32_t l1_context_id : 1;
            uint32_t silicon_debug : 1;
            uint32_t fma_extensions : 1;
            uint32_t cmpxchg16b_instruction : 1;
            uint32_t xtpr_update_control : 1;
            uint32_t perfmon_and_debug_capability : 1;
            uint32_t reserved1 : 1;
            uint32_t process_context_identifiers : 1; // Support for PCIDs
            uint32_t direct_cache_access : 1;
            uint32_t sse41_support : 1;
            uint32_t sse42_support : 1;
            uint32_t x2apic_support : 1;
            uint32_t movbe_instruction : 1;
            uint32_t popcnt_instruction : 1;
            uint32_t tsc_deadline : 1;
            uint32_t aesni_instruction_extensions : 1;
            uint32_t xsave_xrstor_instruction : 1;
            uint32_t osx_save : 1;
            uint32_t avx_support : 1;
            uint32_t half_precision_conversion_instructions : 1;
            uint32_t rdrand_instruction : 1;
            uint32_t reserved2 : 1;
        };

        uint32_t flags;
    } cpuid_feature_information_ecx;

    union {
        struct {
            uint32_t floating_point_unit_on_chip : 1;
            uint32_t virtual_8086_mode_enhancements : 1;
            uint32_t debugging_extensions : 1;
            uint32_t page_size_extension : 1;
            uint32_t timestamp_counter : 1;
            uint32_t rdmsr_wrmsr_instructions : 1;
            uint32_t physical_address_extension : 1; //  Physical addresses greater than 32 bits are supported, 2MB pages supported instead of 5MB pages if set
            uint32_t machine_check_exception : 1;
            uint32_t cmpxchg8b : 1;
            uint32_t apic_on_chip : 1;
            uint32_t reserved1 : 1;
            uint32_t sysenter_sysexit_instructions : 1;
            uint32_t memory_type_range_registers : 1;
            uint32_t page_global_bit : 1; // If set global pages are supported
            uint32_t machine_check_architecture : 1;
            uint32_t conditional_move_instructions : 1;
            uint32_t page_attribute_table : 1;
            uint32_t page_size_extension_36bit : 1;
            uint32_t processor_serial_number : 1;
            uint32_t clflush : 1;
            uint32_t reserved2 : 1;
            uint32_t debug_store : 1;
            uint32_t thermal_control_msrs_for_acpi : 1;
            uint32_t mmx_support : 1;
            uint32_t fxsave_fxrstor_instructions : 1;
            uint32_t sse_support : 1;
            uint32_t sse2_support : 1;
            uint32_t self_snoop : 1;
            uint32_t hyper_threading_technology : 1;
            uint32_t thermal_monitor : 1;
            uint32_t reserved3 : 1;
            uint32_t pending_break_enable : 1;
        };

        uint32_t flags;
    } cpuid_feature_information_edx;

} cpuid_eax_01;

typedef union {
    struct {
        uint64_t reserved1 : 3;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t reserved2 : 7;
        uint64_t address_of_page_directory : 36;
        uint64_t reserved3 : 16;
    };

    uint64_t flags;
} cr3;

typedef union {
    struct {
        uint64_t virtual_mode_extensions : 1;
        uint64_t protected_mode_virtual_interrupts : 1;
        uint64_t timestamp_disable : 1;
        uint64_t debugging_extensions : 1;
        uint64_t page_size_extensions : 1;
        uint64_t physical_address_extension : 1;
        uint64_t machine_check_enable : 1;
        uint64_t page_global_enable : 1;
        uint64_t performance_monitoring_counter_enable : 1;
        uint64_t os_fxsave_fxrstor_support : 1;
        uint64_t os_xmm_exception_support : 1;
        uint64_t usermode_instruction_prevention : 1;
        uint64_t linear_addresses_57_bit : 1;
        uint64_t vmx_enable : 1;
        uint64_t smx_enable : 1;
        uint64_t reserved1 : 1;
        uint64_t fsgsbase_enable : 1;
        uint64_t pcid_enable : 1;
        uint64_t os_xsave : 1;
        uint64_t key_locker_enable : 1;
        uint64_t smep_enable : 1;
        uint64_t smap_enable : 1;
        uint64_t protection_key_enable : 1;
        uint64_t control_flow_enforcement_enable : 1;
        uint64_t protection_key_for_supervisor_mode_enable : 1;
        uint64_t reserved2 : 39;
    };

    uint64_t flags;
} cr4;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t must_be_zero : 1;
        uint64_t ignored_1 : 4;
        uint64_t page_frame_number : 36;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pml4e_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t pat : 1;
        uint64_t reserved1 : 17;
        uint64_t page_frame_number : 18;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pdpte_1gb_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 4;
        uint64_t page_frame_number : 36;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pdpte_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t pat : 1;
        uint64_t reserved1 : 8;
        uint64_t page_frame_number : 27;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pde_2mb_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 4;
        uint64_t page_frame_number : 36;
        uint64_t reserved2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pde_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t pat : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 3;
        uint64_t page_frame_number : 36;
        uint64_t reserved1 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pte_64;

typedef union {

    struct {
        uint64_t offset_1gb : 30;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_2mb : 21;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_4kb : 12;
        uint64_t pte_idx : 9;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    uint64_t flags;
} va_64_t;

typedef struct {
    void* table;
    bool large_page;
} slot_t;

typedef struct {
    va_64_t remapped_va;

    // Pml4 slot not needed as we only have 1 anyways
    slot_t pdpt_table;
    slot_t pd_table;
    void* pt_table;

    bool used;
} remapped_entry_t;

typedef enum {
    pdpt_table_valid, // Means that the pml4 at the correct index already points to a remapped pdpt table
    pde_table_valid,  // Means that the pdpt at the correct index already points to a remapped pde table
    pte_table_valid,  // Means that the pde at the correct index already points to a remapped pte table
    non_valid,        // Means that the pml4 indexes didn't match
} usable_until_t;

#define PAGE_TABLE_ENTRY_COUNT 512
typedef struct {
    alignas(0x1000) pml4e_64 pml4_table[PAGE_TABLE_ENTRY_COUNT]; // Basically only is a windows copy; We replace one entry and point it to our paging structure
    alignas(0x1000) pdpte_64 pdpt_table[PAGE_TABLE_ENTRY_COUNT];
    alignas(0x1000) pde_2mb_64 pd_2mb_table[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
} page_tables_t;

#define REMAPPING_TABLE_COUNT 100
#define MAX_REMAPPINGS 100 
typedef struct {
    union {
        pdpte_64* pdpt_table[REMAPPING_TABLE_COUNT];
        pdpte_1gb_64* pdpt_1gb_table[REMAPPING_TABLE_COUNT];
    };
    union {
        pde_64* pd_table[REMAPPING_TABLE_COUNT];
        pde_2mb_64* pd_2mb_table[REMAPPING_TABLE_COUNT];
    };

    pte_64* pt_table[REMAPPING_TABLE_COUNT];

    bool is_pdpt_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pd_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pt_table_occupied[REMAPPING_TABLE_COUNT];

    remapped_entry_t remapping_list[MAX_REMAPPINGS];
} remapping_tables_t;

typedef struct {
    // These page tables make up our cr3
    page_tables_t* page_tables;

    // These page tables are sole entries we use to
    // remap addresses in our cr3
    remapping_tables_t remapping_tables;

    cr3 kernel_cr3;

    cr3 constructed_cr3;
    uint64_t mapped_physical_mem_base; // Is the base where we mapped the first 512 gb of physical memory 

    bool initialized;
} physmem_t;