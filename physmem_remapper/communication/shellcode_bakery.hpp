#pragma once
#include "comm.hpp"
#include "shared.hpp"
#include "../idt/idt.hpp"

inline uint64_t* function_address_pointer;

namespace executed_gadgets {

	namespace jump_handler {
		void generate_executed_jump_gadget(uint8_t* gadget, uint64_t* my_cr3_storing_region,
			void* mem, uint64_t jmp_address,
			idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region,
			gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region,
			segment_selector* my_tr, segment_selector* my_tr_storing_region);
	};

	namespace return_handler {
		void generate_return_gadget(uint8_t* gadget, uint64_t jump_address,
			uint64_t* my_cr3_storing_region,
			idt_ptr_t* my_idt_storing_region,
			gdt_ptr_t* my_gdt_storing_region,
			segment_selector* my_tr_storing_region);
	};

	namespace gadget_util {
		void generate_address_space_switch_call_function_gadget(uint8_t* gadget, uint64_t* address_space_switching_cr3_storing_region,
			void* function_address,
			idt_ptr_t* kernel_idt_storing_region, idt_ptr_t* address_space_switching_idt_storing_region,
			gdt_ptr_t* kernel_gdt_storing_region, gdt_ptr_t* address_space_switching_gdt_storing_region,
			segment_selector* kernel_tr_storing_region, segment_selector* address_space_switching_tr_storing_region);

		void load_new_function_address_in_gadget(uint64_t new_function);
	};
};

namespace shown_gadgets {
	void generate_shown_jump_gadget(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region);
};