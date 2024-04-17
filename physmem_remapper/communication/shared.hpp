#pragma once
// In UM we need to include intrin.h
#ifndef _KERNEL_MODE
#include <intrin.h>
#endif // _KERNEL_MODE

// Designed to be a standalone, includable .hpp, thus we need to make our own definitions etc.

#define MAX_PATH 260

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

struct module_info_t {
    char name[MAX_PATH];
    uint64_t base;
    uint64_t size;
};

struct allocate_memory_struct {
    // Input
    uint64_t size;

    // Output
    void* memory_base;
};

struct free_memory_struct {
    // Input
    void* memory_base;
};

struct copy_virtual_memory_struct {
    // Input
    uint64_t source_cr3;
    uint64_t destination_cr3;

    uint64_t source;
    uint64_t destination;

    uint64_t size;
};

struct copy_physical_memory_struct {
    // Input
    uint64_t source_physical;   
    uint64_t destination_physical; 
    uint64_t size;             
};

typedef struct read_process_memory_struct {
    uint64_t pid;
    void* virtual_address;
    void* buffer;
    uint64_t size;
    uint64_t* bytes_read;
} read_process_memory_struct;


struct get_cr3_struct {
    // Input
    uint64_t pid;

    // Output
    uint64_t cr3;
};

struct get_module_base_struct {
    // Input
    char module_name[MAX_PATH];
    uint64_t pid;

    // Output
    uint64_t module_base;
};

struct get_module_size_struct {
    // Input
    char module_name[MAX_PATH];
    uint64_t pid;

    // Output
    uint64_t module_size;
};

struct get_physical_address_struct {
    // Input
    uint64_t virtual_address;
    uint64_t cr3;

    // Ouput
    uint64_t physical_address;
};

struct get_virtual_address_struct {
    // Input
    uint64_t physical_address;

    // Output
    uint64_t virtual_address;
};

struct get_pid_by_name_struct {
    // Input
    char name[MAX_PATH];

    // Ouput
    uint64_t pid;
};

struct ensure_mapping_struct {
    // Ouput
    uint64_t base;
    uint64_t size;
};

struct get_driver_info_struct {
    // Ouput
    uint64_t base;
    uint64_t size;
};

struct get_ldr_data_table_entry_count_struct {
    // Input
    uint64_t pid;

    // Output
    uint64_t count;
};

struct cmd_get_data_table_entry_info_struct {
    // Input
    uint64_t pid;
    module_info_t* info_array;
};


enum command_type {
    cmd_allocate_memory,
    cmd_free_memory,
    cmd_copy_virtual_memory,
    cmd_copy_physical_memory,
    cmd_get_cr3,
    cmd_get_module_base,
    cmd_get_module_size,
    cmd_get_pid_by_name,
    cmd_get_physical_address,
    cmd_get_virtual_address,
    cmd_ensure_mapping,
    cmd_get_driver_info,
    cmd_get_ldr_data_table_entry_count,
    cmd_get_data_table_entry_info,
    cmd_comm_test,
    cmd_read_process_memory,
};

struct command {
    bool result;
    uint64_t command_number;
    void* sub_command_ptr;
};


inline uint64_t generate_seed() {
    return __rdtsc();
}

inline uint64_t hash_key(uint32_t input) {
    uint64_t extended_input = static_cast<uint64_t>(input);

    //Initial mix to spread the input bits across the 64-bit space
    uint64_t mix = extended_input ^ (extended_input << 21);
    mix ^= (mix >> 35);
    mix *= 0x9E3779B97F4A7C15ULL;

    // Incorporate additional arithmetic and bitwise operations
    uint64_t rotated = (mix << 28) | (mix >> (64 - 28));
    rotated ^= (rotated * 0xC6A4A7935BD1E995ULL);
    rotated += (rotated << 12);

    // Final mix to ensure input bits affect all parts of the result
    uint64_t hash = rotated ^ (rotated >> 25);
    hash *= 0x2545F4914F6CDD1DULL;
    hash ^= (hash >> 33);

    return hash;
}

inline void generate_keys(uint32_t& flags, uint64_t& dw_data) {
    uint64_t seed = generate_seed();

    uint64_t seed_rotated = _rotl64(seed, seed & 0x1F);
    uint64_t seed_shifted = (seed_rotated >> 16) | (seed_rotated << 48);
    uint64_t key_component = seed ^ seed_shifted ^ (seed_rotated * 0x55AA55AA55AA55AALL);

    // Base key
    flags = static_cast<uint32_t>(key_component ^ (key_component >> 32));

    // Hash of that key
    dw_data = hash_key(flags);
}

inline bool check_keys(uint32_t flags, uint64_t dw_data) {
    // Re-hash the flags using the same hash function
    uint64_t correct_hash = hash_key(flags);

    // Compare the correct hash with the provided dw_data
    return correct_hash == dw_data;
}