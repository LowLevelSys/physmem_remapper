#pragma once
#include "../includes/includes.hpp"
#include "comm.hpp"

using MmAllocateContiguousMemory_t = PVOID(__stdcall*)(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS HighestAcceptableAddress);
using MmFreeContiguousMemory_t = PVOID(__stdcall*)(PVOID BaseAddress);
using MmGetVirtualForPhysical_t = PVOID(__stdcall*)(PHYSICAL_ADDRESS PhysicalAddress);
using MmRemovePhysicalMemory_t = NTSTATUS(__stdcall*)(PPHYSICAL_ADDRESS StartAddress, PLARGE_INTEGER NumberOfBytes);