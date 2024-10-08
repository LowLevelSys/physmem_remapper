#pragma once
#pragma optimize("", off)
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
    _In_ uint64_t src_cr3;
    _In_ uint64_t dst_cr3;

    _In_ void* src;
    _In_ void* dst;

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
    _In_ module_info_t* info_array;
};

#define MAX_MESSAGES 512
#define MAX_MESSAGE_SIZE 256

struct log_entry_t {
    bool present;
    char payload[MAX_MESSAGE_SIZE];
};

struct cmd_output_logs_t {
    _In_ uint32_t count;
    _In_ log_entry_t* log_array;
};

enum call_types_t : uint32_t {
    cmd_get_pid_by_name,
    cmd_get_cr3,

    cmd_get_module_base,
    cmd_get_module_size,
    cmd_get_ldr_data_table_entry_count,
    cmd_get_data_table_entry_info,

    cmd_copy_virtual_memory,

    cmd_output_logs,

    cmd_remove_from_system_page_tables,
    cmd_unload_driver,
    cmd_ping_driver,
};

struct command_t {
    bool status;
    call_types_t call_type;
    void* sub_command_ptr;
};
#pragma optimize("", on)