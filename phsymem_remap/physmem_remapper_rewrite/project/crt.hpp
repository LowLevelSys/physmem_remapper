#pragma once
#include <immintrin.h>

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

namespace crt {
    inline void* memset(void* src, int val, size_t count) {
        unsigned char* ptr = static_cast<unsigned char*>(src);
        uint64_t wide_val = 0x0101010101010101ULL * static_cast<unsigned char>(val);

        // Handle any initial unaligned bytes
        while (reinterpret_cast<uintptr_t>(ptr) % 16 != 0 && count > 0) {
            *ptr++ = static_cast<unsigned char>(val);
            --count;
        }

        // Set memory using 16-byte blocks
        __m128i big_val = _mm_set1_epi8(static_cast<char>(val));
        while (count >= 16) {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(ptr), big_val);
            ptr += 16;
            count -= 16;
        }

        // Handle remaining bytes with 8-byte transfers if possible
        while (count >= 8) {
            *reinterpret_cast<uint64_t*>(ptr) = wide_val;
            ptr += 8;
            count -= 8;
        }

        // Clean up any remaining bytes
        while (count--) {
            *ptr++ = static_cast<unsigned char>(val);
        }

        return src;
    }

    inline void* memmove(void* dest, const void* src, size_t count) {
        char* d = static_cast<char*>(dest);
        const char* s = static_cast<const char*>(src);

        if (d < s) {
            // Forward copy
            while (count >= 16) {
                __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(s));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(d), data);
                d += 16;
                s += 16;
                count -= 16;
            }
            while (count >= 8) {
                *reinterpret_cast<uint64_t*>(d) = *reinterpret_cast<const uint64_t*>(s);
                d += 8;
                s += 8;
                count -= 8;
            }
            while (count--) {
                *d++ = *s++;
            }
        }
        else {
            // Reverse copy
            d += count;
            s += count;
            while (count >= 16) {
                d -= 16;
                s -= 16;
                count -= 16;
                __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(s));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(d), data);
            }
            while (count >= 8) {
                d -= 8;
                s -= 8;
                count -= 8;
                *reinterpret_cast<uint64_t*>(d) = *reinterpret_cast<const uint64_t*>(s);
            }
            while (count--) {
                *--d = *--s;
            }
        }

        return dest;
    }

    inline int memcmp(const void* s1, const void* s2, size_t n) {
        auto p1 = static_cast<const unsigned char*>(s1);
        auto p2 = static_cast<const unsigned char*>(s2);

        while (n >= 32) {
            __m256i v1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p1));
            __m256i v2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p2));

            // 32 bytes comparison
            __m256i result = _mm256_cmpeq_epi8(v1, v2);
            int mask = _mm256_movemask_epi8(result);

            // not all bytes are equal
            if (mask != -1) {
                for (int i = 0; i < 32; ++i) {
                    if (p1[i] != p2[i]) {
                        return p1[i] - p2[i];
                    }
                }
            }

            p1 += 32;
            p2 += 32;
            n -= 32;
        }

        // remaining
        while (n--) {
            if (*p1 != *p2) {
                return *p1 - *p2;
            }
            p1++;
            p2++;
        }

        return 0;
    }

    inline void* memcpy(void* dest, const void* src, size_t count) {
        auto* dst8 = static_cast<char*>(dest);
        const auto* src8 = static_cast<const char*>(src);

        while (count >= 32) {
            __m256i data = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src8));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst8), data);
            src8 += 32;
            dst8 += 32;
            count -= 32;
        }

        // Use 8-byte transfers for remaining data if any
        while (count >= 8) {
            *reinterpret_cast<uint64_t*>(dst8) = *reinterpret_cast<const uint64_t*>(src8);
            src8 += 8;
            dst8 += 8;
            count -= 8;
        }

        while (count--) {
            *dst8++ = *src8++;
        }

        return dest;
    }

    inline int strcmp(const char* s1, const char* s2) {
        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }
        return static_cast<unsigned char>(*s1) - static_cast<unsigned char>(*s2);
    }

    inline int strncmp(const char* s1, const char* s2, size_t n) {
        while (n && *s1 && (*s1 == *s2)) {
            ++s1;
            ++s2;
            --n;
        }
        return n ? (static_cast<unsigned char>(*s1) - static_cast<unsigned char>(*s2)) : 0;
    }

    inline char tolower(char c) {
        if (c >= 'A' && c <= 'Z')
            return c + 32;

        return c;
    }

    inline size_t strlen(const char* str) {
        const char* s = str;
        while (*s) ++s;
        return s - str;
    }

    typedef unsigned short wchar_t;

    inline wchar_t towlower(wchar_t wc) {
        if (wc >= L'A' && wc <= L'Z') {
            return wc + 32;
        }
        return wc;
    }

    inline int _wcsicmp(const wchar_t* s1, const wchar_t* s2) {
        while (*s1 && (towlower(*s1) == towlower(*s2))) {
            ++s1;
            ++s2;
        }
        return towlower(*s1) - towlower(*s2);
    }

    inline const char* strstr(const char* haystack, const char* needle) {
        if (!*needle) return haystack;

        const char* p1 = haystack;
        const char* p2 = needle;

        while (*haystack) {
            if (*haystack == *p2) {
                p1 = haystack;
                while (*p1 && *p2 && (*p1 == *p2)) {
                    ++p1;
                    ++p2;
                }
                if (!*p2) return haystack;
                p2 = needle;
            }
            ++haystack;
        }
        return nullptr;
    }

    inline const char* strrchr(const char* str, int c) {
        const char* last = nullptr;
        while (*str) {
            if (*str == c) {
                last = str;
            }
            ++str;
        }
        return (*str == c) ? str : last;
    }
};