#include <limits>

#include <sstream>

#include <Windows.h>

#include <TlHelp32.h>

#include "Windows.hpp"
#include "drv.hpp"

namespace arch {
WindowsProcess::WindowsProcess(std::string process_name) : Process{} {
    g_proc = process_t::get_inst(process_name);

    if (!g_proc)
        return;

    m_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, g_proc->get_target_pid());
    if (!m_process)
        return;

    // Iterate modules.
	std::vector<module_info_t> modules = g_proc->get_modules();
    for (auto& module : modules) {
        Module m{};

        m.name = module.name;
        m.start = module.base;
        m.size = module.size;
        m.end = m.start + m.size;

        m_modules.emplace_back(std::move(m));
    }
  
    // Iterate memory.
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(m_process, (LPCVOID)address, &mbi, sizeof(mbi)) != 0) {
        auto protect = mbi.Protect;
        Allocation a{};

        a.start = (uintptr_t)mbi.BaseAddress;
        a.size = mbi.RegionSize;
        a.end = a.start + a.size;
        a.read = protect & PAGE_READONLY || protect & PAGE_READWRITE || protect & PAGE_WRITECOPY ||
                 protect & PAGE_EXECUTE_READ || protect & PAGE_EXECUTE_READWRITE || protect & PAGE_EXECUTE_WRITECOPY;
        a.write = protect & PAGE_READWRITE || protect & PAGE_WRITECOPY || protect & PAGE_EXECUTE_READWRITE ||
                  protect & PAGE_EXECUTE_WRITECOPY;
        a.execute = protect & PAGE_EXECUTE_READ || protect & PAGE_EXECUTE_READWRITE || protect & PAGE_EXECUTE_WRITECOPY;

        if (a.read) {
            // We cache read-only memory allocations in their entirety because Process::read optimizes for read-only
            // reads.
            if (!a.write) {
                ReadOnlyAllocation ro{};
                ro.start = a.start;
                ro.size = a.size;
                ro.end = a.end;
                ro.read = a.read;
                ro.write = a.write;
                ro.execute = a.execute;
                ro.mem.resize(ro.size);

                if (read(ro.start, ro.mem.data(), ro.size))
                    m_read_only_allocations.emplace_back(std::move(ro));
            }

            m_allocations.emplace_back(std::move(a));
        }

        address += mbi.RegionSize;
    }
}

uint32_t WindowsProcess::process_id() {
    return g_proc->get_target_pid();
}

bool WindowsProcess::ok() {
    if (m_process == nullptr)
        return false;

    DWORD exitcode{};

    GetExitCodeProcess(m_process, &exitcode);

    return exitcode == STILL_ACTIVE;
}

bool WindowsProcess::handle_write(uintptr_t address, void* buffer, size_t size) {
    return g_proc->write((void*)address, buffer, size);
}

bool WindowsProcess::handle_read(uintptr_t address, void* buffer, size_t size) {
    return g_proc->read_array(buffer, (void*)address, size);
}

// remove allocation and protection stuff for now.
std::optional<uintptr_t> WindowsProcess::handle_allocate(uintptr_t address, size_t size, uint64_t flags) {
   /* 
   if (auto ptr = VirtualAllocEx(m_process, (LPVOID)address, size, MEM_COMMIT, (DWORD)flags); ptr != nullptr)
        return (uintptr_t)ptr;
   */

    return std::nullopt;
}

std::optional<uint64_t> WindowsProcess::handle_protect(uintptr_t address, size_t size, uint64_t flags) {
    /*
    DWORD old_protect{};
    if (VirtualProtectEx(m_process, (LPVOID)address, size, (DWORD)flags, &old_protect) != 0)
        return (uint64_t)old_protect;
    */

    return std::nullopt;
}

std::optional<uintptr_t> WindowsProcess::get_complete_object_locator_ptr_from_vtable(uintptr_t vtable) {
    if (vtable == 0)
        return std::nullopt;

    return Process::read<uintptr_t>(vtable - sizeof(void*));
}

std::optional<uintptr_t> WindowsProcess::get_complete_object_locator_ptr(uintptr_t ptr) {
    if (ptr == 0)
        return std::nullopt;

    auto vtable = Process::read<uintptr_t>(ptr);
    if (!vtable || *vtable == 0)
        return std::nullopt;

    return get_complete_object_locator_ptr_from_vtable(*vtable);
}

std::optional<_s_RTTICompleteObjectLocator> WindowsProcess::get_complete_object_locator(uintptr_t ptr) {
    auto out_ptr = get_complete_object_locator_ptr(ptr);
    if (!out_ptr)
        return std::nullopt;

    return Process::read<_s_RTTICompleteObjectLocator>(*out_ptr);
}

std::optional<std::array<uint8_t, sizeof(std::type_info) + 256>> WindowsProcess::try_get_typeinfo_from_locator(uintptr_t locator_ptr) {
    auto locator = Process::read<_s_RTTICompleteObjectLocator>(locator_ptr);
    if (!locator)
        return std::nullopt;

    auto type_desc_pre = locator->pTypeDescriptor;

    // x64 usually
#if _RTTI_RELATIVE_TYPEINFO
    if (type_desc_pre == 0) {
        return std::nullopt;
    }

    uintptr_t image_base = 0;

    if (locator->signature == COL_SIG_REV0) {
        auto module_within = get_module_within(locator_ptr);
        if (!module_within)
            return std::nullopt;

        image_base = module_within->start;
    } else
        image_base = locator_ptr - locator->pSelf;

    auto ti = image_base + type_desc_pre;

    return Process::read<std::array<uint8_t, sizeof(std::type_info) + 256>>((uintptr_t)ti);
#else
    if (type_desc_pre == nullptr || get_module_within((uintptr_t)type_desc_pre) == nullptr) {
        return std::nullopt;
    }

    return Process::read<std::array<uint8_t, sizeof(std::type_info) + 256>>((uintptr_t)type_desc_pre);
#endif
}

std::optional<std::array<uint8_t, sizeof(std::type_info) + 256>> WindowsProcess::try_get_typeinfo_from_ptr(uintptr_t ptr) {
    if (ptr == 0)
        return std::nullopt;

    auto locator_ptr = get_complete_object_locator_ptr(ptr);
    if (!locator_ptr || *locator_ptr == 0)
        return std::nullopt;

    return try_get_typeinfo_from_locator(*locator_ptr);
}

std::optional<std::array<uint8_t, sizeof(std::type_info) + 256>> WindowsProcess::try_get_typeinfo_from_vtable(uintptr_t vtable) {
    if (vtable == 0)
        return std::nullopt;

    auto locator_ptr = get_complete_object_locator_ptr_from_vtable(vtable);
    if (!locator_ptr || *locator_ptr == 0)
        return std::nullopt;

    return try_get_typeinfo_from_locator(*locator_ptr);
}

HANDLE WindowsProcess::create_remote_thread(uintptr_t address, uintptr_t param) {
    return nullptr; //CreateRemoteThread(m_process, nullptr, 0, (LPTHREAD_START_ROUTINE)address, (LPVOID)param, 0, nullptr);
}

std::optional<std::string> WindowsProcess::get_typename(uintptr_t ptr) {
    if (ptr == 0)
        return std::nullopt;

    auto vtable = Process::read<uintptr_t>(ptr);
    if (!vtable || *vtable == 0)
        return std::nullopt;

    return get_typename_from_vtable(*vtable);
}

std::optional<std::string> WindowsProcess::get_typename_from_vtable(uintptr_t ptr) try {
    if (ptr == 0)
        return std::nullopt;

    auto typeinfo = try_get_typeinfo_from_vtable(ptr);
    if (!typeinfo)
        return std::nullopt;

    auto ti = (std::type_info*)&*typeinfo;
    if (ti->raw_name()[0] != '.' || ti->raw_name()[1] != '?')
        return std::nullopt;

    if (std::string_view{ti->raw_name()}.find("@") == std::string_view::npos)
        return std::nullopt;

    auto raw_data = (__std_type_info_data*)((uintptr_t)ti + sizeof(void*));
    raw_data->_UndecoratedName = nullptr; // fixes a crash if memory already allocated because it's not allocated by us

    const auto result = std::string_view{ ti->name() };
    if (result.empty() || result == " ")
        return std::nullopt;

    return std::string{result};
} catch(...) {
    return std::nullopt;
}

std::map<uint32_t, std::string> WindowsHelpers::processes() {
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return {};

    std::map<uint32_t, std::string> pids{};
    PROCESSENTRY32 entry{};

    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            pids[entry.th32ProcessID] = entry.szExeFile;
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    return pids;
}
} // namespace arch
