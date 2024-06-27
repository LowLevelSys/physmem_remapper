#pragma once
#include "includes.h"

// Information that is stored per "loaded" process
struct per_process_struct {
	uint64_t target_pid;
	uint64_t target_cr3;
};