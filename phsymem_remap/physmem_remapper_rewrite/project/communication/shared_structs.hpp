#pragma once
// Designed to be a standalone, includable .hpp, thus we need to make our own definitions etc.

/*
    Typedefs and Definitions
*/

#ifndef _In_
#define _In_
#endif // !_In_

#ifndef _Out_
#define _Out_
#endif // !_Out_

#ifndef MAX_PATH
#define MAX_PATH 260
#endif // !MAX_PATH

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

/*
    Communication structs
*/

struct copy_virtual_memory_t {
    _In_ uint64_t source_cr3;
    _In_ uint64_t destination_cr3;

    _In_ void* source;
    _In_ void* destination;

    _In_ uint64_t size;
};

struct get_cr3_t {
    _In_ uint64_t pid;

    _Out_ uint64_t cr3;
};

struct get_module_base_t {
    _In_ char module_name[MAX_PATH];
    _In_ uint64_t pid;

    _Out_ uint64_t module_base;
};

struct get_module_size_t {
    _In_ char module_name[MAX_PATH];
    _In_ uint64_t pid;

    _Out_ uint64_t module_size;
};

struct get_pid_by_name_t {
    _In_ char name[MAX_PATH];

    _Out_ uint64_t pid;
};

struct get_ldr_data_table_entry_count_t {
    _In_ uint64_t pid;

    _Out_ uint64_t count;
};

struct module_info_t {
    _In_ char name[MAX_PATH];
    _In_ uint64_t base;
    _In_ uint64_t size;
};

struct cmd_get_data_table_entry_info_t {
    _In_ uint64_t pid;

    _Out_ module_info_t* info_array;
};

struct cmd_get_eprocess {
    _In_ uint64_t pid;

    _Out_ void* eproc;
};

enum call_types_t : uint32_t {
    cmd_get_pid_by_name,
    cmd_get_cr3,

    cmd_get_module_base,
    cmd_get_module_size,
    cmd_get_ldr_data_table_entry_count,
    cmd_get_data_table_entry_info,

    cmd_copy_virtual_memory,

    cmd_remove_apc,
    cmd_restore_apc,
    
    cmd_get_eproc
};

struct command_t {
    bool status;
    call_types_t call_type;
    void* sub_command_ptr;
};