#include "../physmem/physmem.hpp"
#include "../physmem/remapping.hpp"

#include <ntimage.h>

// Structs
typedef struct
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    //enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS* Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

// We only need to define a macro for comm logging, no testing needed
#define ENABLE_COMMUNICATION_LOGGING
#define ENABLE_COMMUNICATION_TESTS

// Global declarations
extern "C" PLIST_ENTRY PsLoadedModuleList;
extern "C" NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS PROCESS, PKAPC_STATE ApcState);
extern "C" NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

typedef __int64(__fastcall* orig_NtUserGetCPD_type)(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data);

// Global variables
inline paging_structs::cr3 global_kernel_cr3;

inline uint64_t global_orig_data_ptr;
inline uint64_t global_new_data_ptr;
inline uint64_t* global_data_ptr_address;
inline orig_NtUserGetCPD_type orig_NtUserGetCPD;

// Func declarations
bool init_communication(void);
__int64 __fastcall handler(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data);

// Helper functions
inline void* get_driver_module_base(const wchar_t* module_name) {
    PLIST_ENTRY head = PsLoadedModuleList;
    PLIST_ENTRY curr = head->Flink;

    // Just loop over the modules
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (crt::_wcsicmp(curr_mod->BaseDllName.Buffer, module_name) == 0) {
            return curr_mod->DllBase;
        }

        curr = curr->Flink;
    }

    return 0;
}

inline PEPROCESS get_eprocess(const char* process_name) {
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    char image_name[15];

    do {
        crt::memcpy((void*)(&image_name), (void*)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

        if (crt::strstr(image_name, process_name)) {
            uint32_t active_threads;

            crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + 0x5f0), sizeof(active_threads));
            if (active_threads) {
                return curr_entry;
            }
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curr_entry != sys_process);

    return 0;
}

inline uintptr_t find_pattern_in_range(uintptr_t region_base, size_t region_size, const char* pattern, size_t pattern_size, char wildcard) {
    // Ensure there are enough bytes left to check the pattern
    char* region_end = (char*)region_base + region_size - pattern_size + 1;

    for (char* byte = (char*)region_base; byte < region_end; ++byte) {
        if (*byte == *pattern || *pattern == wildcard) {
            bool found = true;

            for (size_t i = 1; i < pattern_size; ++i) {
                if (pattern[i] != byte[i] && pattern[i] != wildcard) {
                    found = false;
                    break;  // break out of this inner loop as soon as mismatch is found
                }
            }
            if (found) {
                return (uintptr_t)byte;
            }
        }
    }

    return 0;
}

inline uintptr_t search_pattern_in_section(void* module_handle, const char* section_name, const char* pattern, uint64_t pattern_size, char wildcard) {

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_handle;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        dbg_log("Invalid dos headers");
        return 0;
    }

    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uintptr_t)module_handle + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        dbg_log("Invalid nt headers");
        return 0;
    }

    // First section header is directly after NT Headers
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uintptr_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));

    for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        // Check if this is the section we are interested in
        if (crt::strncmp((const char*)sections[i].Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            // Calculate the start address of the section
            uint8_t* section_start = (uint8_t*)module_handle + sections[i].VirtualAddress;
            uint32_t section_size = sections[i].Misc.VirtualSize;

            uintptr_t result = find_pattern_in_range((uintptr_t)section_start, section_size, pattern, pattern_size, wildcard);

            if (!result)
                dbg_log("Pattern not found in the section");

            return result;
        }
    }

    dbg_log("Didn't find section %s", section_name);

    return 0; // Pattern not found
} 