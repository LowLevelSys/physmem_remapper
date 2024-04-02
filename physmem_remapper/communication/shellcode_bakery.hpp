#include "comm.hpp"
#include "shared.hpp"
#include "../idt/idt.hpp"


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
};

namespace shown_gadgets {
	void generate_shown_jump_gadget(uint8_t* gadget, void* mem, uint64_t* my_cr3_storing_region);
};