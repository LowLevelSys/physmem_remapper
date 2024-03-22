#include "idt.hpp"

extern "C" int _fltused = 0; // Compiler issues

extern "C" void handle_non_maskable_interrupt(trap_frame_t* trap_frame) {
	UNREFERENCED_PARAMETER(trap_frame);

	// To do: Implement a system to hide from eac nmi's
}

idt_ptr_t get_idt_ptr() {
	idt_ptr_t idtr;

	idtr.limit = sizeof(my_idt_table) - 1;
	idtr.base = reinterpret_cast<uint64_t>(&my_idt_table);

	return idtr;
}

idt_entry_t create_interrupt_gate(void* handler_address) {
	idt_entry_t entry = { 0 };

	uint64_t offset = reinterpret_cast<uint64_t>(handler_address);

	entry.offset_low = (offset >> 0) & 0xFFFF;
	entry.offset_middle = (offset >> 16) & 0xFFFF;
	entry.offset_high = (offset >> 32) & 0xFFFFFFFF;

	entry.segment_selector = __read_cs();
	entry.gate_type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
	entry.present = true;

	return entry;
}

void init_idt(void) {
	idt_ptr_t idt;
	__sidt(&idt);

	crt::memset(my_idt_table, 0, sizeof(my_idt_table[0]) * 256);

#ifdef PARTIALLY_USE_SYSTEM_IDT
	// Copy over the "normal" kernel idt
	crt::memcpy(my_idt_table, (void*)idt.base, idt.limit);
#endif // PARTIALLY_USE_SYSTEM_IDT

	// Replace the nmi handler
	my_idt_table[NMI_HANDLER_VECTOR] = create_interrupt_gate(asm_non_maskable_interrupt_handler);

	// Idt compatible
	my_idt_ptr = get_idt_ptr();

#ifdef EXTENSIVE_IDT_LOGGING
#ifndef PARTIALLY_USE_SYSTEM_IDT


	dbg_log_idt("Idt initialized \n");

	for (uint64_t i = 0; i < 256; i++) {
		if (my_idt_table[i].present) {
			uint64_t handler_address = (static_cast<uint64_t>(my_idt_table[i].offset_high) << 32) |
				(static_cast<uint64_t>(my_idt_table[i].offset_middle) << 16) |
				(my_idt_table[i].offset_low);
			dbg_log_idt("Idt Entry %llu at %p", i, (void*)handler_address);
		}
	}

	dbg_log("\n");
#endif // !PARTIALLY_USE_SYSTEM_IDT
#endif // EXTENSIVE_IDT_LOGGING
}