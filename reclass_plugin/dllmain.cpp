#include "includes.h"
#include "reclass_structs.h"
#include "eproc.h"
#include "info_storage_structs.h"
#include "driver/driver_um_lib.hpp"
#include "windows_offsets.h"

/*
	Actually used and working exposed API's
*/

extern "C" __declspec(dllexport) void RC_CallConv EnumerateProcesses(EnumerateProcessCallback call_back) {
	if (!call_back)
		return;

	driver_data::init_driver();

	void* sys_eproc = driver_data::physmem_instance->get_eprocess(4);
	void* curr_eproc = sys_eproc;

	do {
		if (!driver_data::is_x64_proc(curr_eproc)) {
			curr_eproc = driver_data::get_next_eprocess(curr_eproc);
			continue;
		}

		if (!driver_data::is_running_process(curr_eproc)) {
			curr_eproc = driver_data::get_next_eprocess(curr_eproc);
			continue;
		}

		EnumerateProcessData curr_proc_data = { 0 };
		if (!driver_data::get_proc_data(curr_eproc, &curr_proc_data)) {
			curr_eproc = driver_data::get_next_eprocess(curr_eproc);
			continue;
		}

		call_back(&curr_proc_data);

		curr_eproc = driver_data::get_next_eprocess(curr_eproc);
	} while (curr_eproc && (curr_eproc != sys_eproc));
}

extern "C" __declspec(dllexport) bool RC_CallConv ReadRemoteMemory(RC_Pointer pid, RC_Pointer address, RC_Pointer buffer, int offset, int size) {
	driver_data::init_driver();

	uint64_t target_cr3 = 0;

	for (const auto& process : driver_data::process_vector) {
		if (process.target_pid == reinterpret_cast<uint64_t>(pid)) {
			target_cr3 = process.target_cr3;
			break;
		}
	}

	if (target_cr3 == 0)
		return false;

	void* src_addr = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(address) + offset);
	void* dest_addr = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(buffer) + offset);
	
	// NOTE!: Pid = 0 for some reason

	bool result = driver_data::physmem_instance->copy_virtual_memory(target_cr3, driver_data::owner_cr3, src_addr, dest_addr, size);

	return result;
}

extern "C" __declspec(dllexport) bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size) {
	driver_data::init_driver();

	uint64_t target_cr3 = 0;

	// Find the target_cr3 for the given process handle (PID)
	for (const auto& process : driver_data::process_vector) {
		if (process.target_pid == reinterpret_cast<uint64_t>(handle)) {
			target_cr3 = process.target_cr3;
			break;
		}
	}

	if (target_cr3 == 0)
		return false;

	void* src_addr = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(buffer) + offset);
	void* dest_addr = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(address) + offset);

	bool result = driver_data::physmem_instance->copy_virtual_memory(driver_data::owner_cr3, target_cr3, src_addr, dest_addr, size);

	return result;
}


// We use pid as a handle as we don't need it and it is usefuly in ReadRemoteMemory and WriteRemoteMemory
extern "C" __declspec(dllexport) RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess desiredAccess) {
	log("Using PID %p as a handle", id);
	return id;
}

extern "C" __declspec(dllexport) bool RC_CallConv IsProcessValid(RC_Pointer handle) {
	if (handle)
		return true;

	return false;
}


/*
	From here on out all functions are not used / are only dummy functions
	To do: Add debugger support via a hv
*/

extern "C" __declspec(dllexport) void RC_CallConv CloseRemoteProcess(RC_Pointer handle) {
}
extern "C" __declspec(dllexport) void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action) {
}
extern "C" __declspec(dllexport) bool RC_CallConv AttachDebuggerToProcess(RC_Pointer id) {
	return false;
}
extern "C" __declspec(dllexport) void RC_CallConv DetachDebuggerFromProcess(RC_Pointer id) {

}
extern "C" __declspec(dllexport) bool RC_CallConv AwaitDebugEvent(DebugEvent* evt, int timeoutInMilliseconds) {
	return false;
}
extern "C" __declspec(dllexport) void RC_CallConv HandleDebugEvent(DebugEvent* evt) {

}
extern "C" __declspec(dllexport) bool RC_CallConv SetHardwareBreakpoint(RC_Pointer id, RC_Pointer address, HardwareBreakpointRegister reg, HardwareBreakpointTrigger type, HardwareBreakpointSize size, bool set) {
	return false;
}
extern "C" __declspec(dllexport) void RC_CallConv EnumerateRemoteSectionsAndModules(RC_Pointer handle, EnumerateRemoteSectionsCallback callbackSection, EnumerateRemoteModulesCallback callbackModule) {
}
