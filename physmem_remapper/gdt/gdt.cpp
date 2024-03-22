#include "gdt.hpp"

bool check_cpu_gdt_allocation(per_vcpu_gdt_t* cpu_gdt) {
	if (!cpu_gdt->ist1 || !cpu_gdt->ist1
		|| !cpu_gdt->ist2 || !cpu_gdt->ist3
		|| !cpu_gdt->ist4 || !cpu_gdt->ist5
		|| !cpu_gdt->ist6 || !cpu_gdt->ist7
		|| !cpu_gdt->rsp0 || !cpu_gdt->rsp1
		|| !cpu_gdt->rsp2)
		return false;

	return true;
}

/*
	Allocates gdt structs for our gdt
	Example access:
	auto tss = my_gdt_state.cpu_gdt_state[2].my_tss;
*/
bool allocate_gdt_structures(void) {
	my_gdt_state.core_count = KeQueryActiveProcessorCount(0);
	PHYSICAL_ADDRESS max_addr = { 0 };
	max_addr.QuadPart = MAXULONG64;

	// Allocate memory for each core's gdt state
	my_gdt_state.cpu_gdt_state = (per_vcpu_gdt_t*)MmAllocateContiguousMemory(sizeof(per_vcpu_gdt_t) * my_gdt_state.core_count, max_addr);

	if (!my_gdt_state.cpu_gdt_state) {
		dbg_log("Failed to allocate gdt state");
		return false;
	}

	gdt_ptrs = (gdt_ptr_t*)MmAllocateContiguousMemory(sizeof(gdt_ptr_t) * my_gdt_state.core_count, max_addr);
	gdt_storing_region = (gdt_ptr_t*)MmAllocateContiguousMemory(sizeof(gdt_ptr_t) * my_gdt_state.core_count, max_addr);

	if (!gdt_ptrs|| !gdt_storing_region) {
		dbg_log("Failed to allcoate gdt ptr list");
		return false;
	}

	crt::memset(my_gdt_state.cpu_gdt_state, 0, sizeof(per_vcpu_gdt_t) * my_gdt_state.core_count);
	crt::memset(gdt_ptrs, 0, sizeof(gdt_ptr_t) * my_gdt_state.core_count);
	crt::memset(gdt_storing_region, 0, sizeof(gdt_ptr_t) * my_gdt_state.core_count);

	for (uint64_t i = 0; i < my_gdt_state.core_count; i++) {
		my_gdt_state.cpu_gdt_state[i].rsp0 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].rsp1 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].rsp2 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);

		my_gdt_state.cpu_gdt_state[i].ist1 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].ist2 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].ist3 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].ist4 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].ist5 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].ist6 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		my_gdt_state.cpu_gdt_state[i].ist7 = (unsigned char*)MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);

		if (!check_cpu_gdt_allocation(&my_gdt_state.cpu_gdt_state[i])) {
			dbg_log("Failed per vcpu gdt Stack Allocation");
			return false;
		}
	}

	return true;
}

uint64_t segment_base(gdt_ptr_t& gdtr, segment_selector selector) {
	if (!selector.index)
		return 0;

	segment_descriptor_64* descriptor = (segment_descriptor_64*)(gdtr.base + (uint64_t)(selector.index) * 8);

	uint64_t base_address =
		(uint64_t)(descriptor->base_address_low) |
		((uint64_t)(descriptor->base_address_middle) << 16) |
		((uint64_t)(descriptor->base_address_high) << 24);

	if (descriptor->descriptor_type == SEGMENT_DESCRIPTOR_TYPE_SYSTEM)
		base_address |= ((uint64_t)(descriptor->base_address_upper) << 32);

	return base_address;
}

gdt_ptr_t get_gdt_ptr(per_vcpu_gdt_t& cpu_gdt_state) {
	gdt_ptr_t gdtr;

	gdt_ptr_t sys_gdt_value = { 0 };
	_sgdt(&sys_gdt_value);

	gdtr.limit = sys_gdt_value.limit; // Just use the system table basically
	gdtr.base = reinterpret_cast<uint64_t>(&cpu_gdt_state.my_gdt); // Point it to our gdt though

	cpu_gdt_state.gdt_ptr = gdtr;

	return gdtr;
}

bool init_gdt(void) {

	if (!allocate_gdt_structures())
		return false;
 
	// For each core load the gdt
	for (uint64_t i = 0; i < my_gdt_state.core_count; i++) {
		KAFFINITY orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

		per_vcpu_gdt_t& curr_gdt_state = my_gdt_state.cpu_gdt_state[i];

		uint16_t tr_index = __read_tr().index;
		gdt_ptr_t gdt_value = { 0 };
		_sgdt(&gdt_value);

		if (!gdt_value.base) {
			KeRevertToUserAffinityThreadEx(orig_affinity);
			return false;
		}

		crt::memcpy(&curr_gdt_state.my_tss, (void*)segment_base(gdt_value, __read_tr()), sizeof(task_state_segment_64));
		crt::memcpy(&curr_gdt_state.my_gdt, (void*)(gdt_value.base), gdt_value.limit);

		// Then point our gdt at the tr index to our tss
		tss_addr base = (tss_addr)&curr_gdt_state.my_tss;
		segment_descriptor_64& curr_gdt_tr = my_gdt_state.cpu_gdt_state->my_gdt[tr_index];

		curr_gdt_tr.base_address_low = base.base_address_low;
		curr_gdt_tr.base_address_middle = base.base_address_middle;
		curr_gdt_tr.base_address_high = base.base_address_high;
		curr_gdt_tr.base_address_upper = base.base_address_upper;

		// In our tss then switch out all stacks (rsp and ist)
		task_state_segment_64& curr_tss = my_gdt_state.cpu_gdt_state[i].my_tss;

		// Privilege stacks
		curr_tss.rsp0 = (uint64_t)curr_gdt_state.rsp0 + KERNEL_STACK_SIZE;
		curr_tss.rsp1 = (uint64_t)curr_gdt_state.rsp1 + KERNEL_STACK_SIZE;
		curr_tss.rsp2 = (uint64_t)curr_gdt_state.rsp2 + KERNEL_STACK_SIZE;

		//Interrupt stacks
		curr_tss.ist1 = (uint64_t)curr_gdt_state.ist1 + KERNEL_STACK_SIZE;
		curr_tss.ist2 = (uint64_t)curr_gdt_state.ist2 + KERNEL_STACK_SIZE;
		curr_tss.ist3 = (uint64_t)curr_gdt_state.ist3 + KERNEL_STACK_SIZE;
		curr_tss.ist4 = (uint64_t)curr_gdt_state.ist4 + KERNEL_STACK_SIZE;
		curr_tss.ist5 = (uint64_t)curr_gdt_state.ist5 + KERNEL_STACK_SIZE;
		curr_tss.ist6 = (uint64_t)curr_gdt_state.ist6 + KERNEL_STACK_SIZE;
		curr_tss.ist7 = (uint64_t)curr_gdt_state.ist7 + KERNEL_STACK_SIZE;

		// Save our curr gdt ptr
		gdt_ptrs[i] = get_gdt_ptr(curr_gdt_state);

		KeRevertToUserAffinityThreadEx(orig_affinity);
	}

	return true;
}