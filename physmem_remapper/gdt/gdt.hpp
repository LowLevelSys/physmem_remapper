#pragma once
#include "../physmem/physmem.hpp"
#include "../physmem/remapping.hpp"

#include <ntimage.h>

bool init_gdt(void);

#define SEGMENT_DESCRIPTOR_TYPE_SYSTEM 0x00000000
#define SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE 0x00000009
#define SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY 0x0000000B

#pragma pack(push, 1)
typedef struct {
    uint32_t reserved_0;

    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;

    uint64_t reserved_1;

    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;

    uint64_t reserved_2;
    uint16_t reserved_3;
    uint16_t io_map_base;
} task_state_segment_64;
#pragma pack(pop)

#pragma pack(push, 1)
struct gdt_ptr_t {
    uint16_t limit;
    uint64_t base;
};
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint16_t segment_limit_low;
    uint16_t base_address_low;
    union {
        struct {
            uint32_t base_address_middle : 8;
            uint32_t type : 4;
            uint32_t descriptor_type : 1;
            uint32_t descriptor_privilege_level : 2;
            uint32_t present : 1;
            uint32_t segment_limit_high : 4;
            uint32_t system : 1;
            uint32_t long_mode : 1;
            uint32_t default_big : 1;
            uint32_t granularity : 1;
            uint32_t base_address_high : 8;
        };

        uint32_t flags;
    };

} segment_descriptor_32;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint16_t segment_limit_low;
    uint16_t base_address_low;

    union {
        struct {
            uint32_t base_address_middle : 8;
            uint32_t type : 4;
            uint32_t descriptor_type : 1;
            uint32_t descriptor_privilege_level : 2;
            uint32_t present : 1;
            uint32_t segment_limit_high : 4;
            uint32_t system : 1;
            uint32_t long_mode : 1;
            uint32_t default_big : 1;
            uint32_t granularity : 1;
            uint32_t base_address_high : 8;
        };

        uint32_t flags;
    };

    uint32_t base_address_upper;
    uint32_t must_be_zero;
} segment_descriptor_64;
#pragma pack(pop)

#pragma pack(push, 1)
typedef union {
    struct {
        uint16_t request_privilege_level : 2;
        uint16_t table : 1;
        uint16_t index : 13;
    };

    uint16_t flags;
} segment_selector;
#pragma pack(pop)

union tss_addr
{
    void* addr;
    struct
    {
        uint64_t base_address_low : 16;
        uint64_t base_address_middle : 8;
        uint64_t base_address_high : 8;
        uint64_t base_address_upper : 32;
    };
};

struct per_vcpu_gdt_t {
    __declspec(align(0x1000)) segment_descriptor_32 my_gdt[8192];
    __declspec(align(0x1000)) task_state_segment_64 my_tss;

    gdt_ptr_t gdt_ptr;

    // Privilege Stacks
    unsigned char* rsp0;
    unsigned char* rsp1;
    unsigned char* rsp2;

    // Interrupt Stacks
    unsigned char* ist1;
    unsigned char* ist2;
    unsigned char* ist3;
    unsigned char* ist4;
    unsigned char* ist5;
    unsigned char* ist6;
    unsigned char* ist7;
};

struct my_gdt_t {
    per_vcpu_gdt_t* cpu_gdt_state;

    uint64_t core_count;
};

inline gdt_ptr_t* gdt_ptrs;
inline gdt_ptr_t* gdt_storing_region;

inline segment_selector* tr_ptrs;
inline segment_selector* tr_storing_region;


inline my_gdt_t my_gdt_state = { 0 };

uint64_t segment_base(gdt_ptr_t& gdtr, segment_selector selector);

extern "C" segment_selector _str(void);
extern "C" void _ltr(uint16_t tr);
extern "C" segment_selector __read_cs(void);

extern "C" void _sgdt(void* gdtr);
extern "C" void _lgdt(void* gdtr);