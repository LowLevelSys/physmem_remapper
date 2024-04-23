#pragma once
#include "../idt/idt_structs.hpp"
#include "../includes/crt.hpp"
#include "../physmem/physmem.hpp"
#include "../idt/idt.hpp"

#define ENABLE_SAFE_CRT_LOGGING

#ifdef ENABLE_SAFE_CRT_LOGGING
#define dbg_log_safe_crt(fmt, ...) dbg_log("[SAFE-CRT] " fmt, ##__VA_ARGS__)
#else
#define dbg_log_safe_crt(fmt, ...) (void)0
#endif

namespace safe_crt {

    inline void* memset(void* src, int val, size_t count) {
        if (!is_idt_inited)
            return crt::memset(src, val, count);

        void* ret = 0;
        idt_ptr_t idt;
        __sidt(&idt);
        __lidt(&my_idt_ptr);

        __try {
            ret = crt::memset(src, val, count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to memset %p to val %d with size %p", src, val, count);
            __lidt(&idt);
            return 0;
        }

        __lidt(&idt);
        return ret;
    }

    inline void* memmove(void* dest, const void* src, size_t count) {
        if (!is_idt_inited)
            return crt::memmove(dest, src, count);

        void* ret = 0;
        __try {
            ret = crt::memmove(dest, src, count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to memmove from %p to %p with size %p", src, dest, count);
            return 0;
        }
        return ret;
    }

    inline int memcmp(const void* s1, const void* s2, size_t n) {
        if (!is_idt_inited)
            return crt::memcmp(s1, s2, n);

        int ret = 0;
        __try {
            ret = crt::memcmp(s1, s2, n);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to memcmp between %p and %p with size %p", s1, s2, n);
            return 0;
        }
        return ret;
    }

    inline void* memcpy(void* dest, const void* src, size_t count) {
        if (!is_idt_inited)
            return crt::memcpy(dest, src, count);

        void* ret = 0;
        __try {
            ret = crt::memcpy(dest, src, count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to memcpy from %p to %p with size %p", src, dest, count);
            return 0;
        }
        return ret;
    }

    inline int strcmp(const char* cs, const char* ct) {
        if (!is_idt_inited)
            return crt::strcmp(cs, ct);

        int ret = 0;
        __try {
            ret = crt::strcmp(cs, ct);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to compare strings %s and %s", cs, ct);
            return 0;
        }
        return ret;
    }

    inline int strncmp(const char* s1, const char* s2, size_t n) {
        if (!is_idt_inited)
            return crt::strncmp(s1, s2, n);

        int ret = 0;
        __try {
            ret = crt::strncmp(s1, s2, n);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to strncmp between %s and %s with n %p", s1, s2, n);
            return 0;
        }
        return ret;
    }

    inline char tolower(char c) {
        if (!is_idt_inited)
            return crt::tolower(c);

        char ret = 0;
        __try {
            ret = crt::tolower(c);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to tolower char %c", c);
            return 0;
        }
        return ret;
    }

    inline size_t strlen(const char* str) {
        if (!is_idt_inited)
            return crt::strlen(str);

        size_t ret = 0;
        __try {
            ret = crt::strlen(str);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to calculate strlen for %s", str);
            return 0;
        }
        return ret;
    }

    inline wchar_t towlower(wchar_t wc) {
        if (!is_idt_inited)
            return crt::towlower(wc);

        wchar_t ret = 0;
        __try {
            ret = crt::towlower(wc);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to convert wchar_t %c to lower", wc);
            return 0;
        }
        return ret;
    }

    inline int _wcsicmp(const wchar_t* s1, const wchar_t* s2) {
        if (!is_idt_inited)
            return crt::_wcsicmp(s1, s2);

        int ret = 0;
        __try {
            ret = crt::_wcsicmp(s1, s2);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to case-insensitive compare wide strings %ls and %ls", s1, s2);
            return 0;
        }
        return ret;
    }

    inline const char* strstr(const char* haystack, const char* needle) {
        if (!is_idt_inited)
            return crt::strstr(haystack, needle);

        const char* ret = 0;
        __try {
            ret = crt::strstr(haystack, needle);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbg_log_safe_crt("Failed to find string %s in %s", needle, haystack);
            return 0;
        }
        return ret;
    }
}
