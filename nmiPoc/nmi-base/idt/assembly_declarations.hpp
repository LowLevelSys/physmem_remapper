#pragma once
#include "idt.hpp"

// Assembly declarations
extern "C" void asm_nmi_handler(void);
extern "C" uint16_t __read_cs(void);

// Windows APIs
extern "C" PLIST_ENTRY PsLoadedModuleList;