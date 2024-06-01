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

    inline int strcmp(const char* cs, const char* ct) {
        if (cs && ct) {
            while (*cs == *ct) {
                if (*cs == 0 && *ct == 0)
                    return 0;

                if (*cs == 0 || *ct == 0)
                    break;
                cs++;
                ct++;
            }

            return *cs - *ct;
        }

        return -1;
    }

    inline int strncmp(const char* s1, const char* s2, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            if (s1[i] == '\0' || s2[i] == '\0') {
                return (unsigned char)s1[i] - (unsigned char)s2[i];
            }
            if (s1[i] != s2[i]) {
                return (unsigned char)s1[i] - (unsigned char)s2[i];
            }
        }

        return 0;
    }

    inline char tolower(char c) {
        if (c >= 'A' && c <= 'Z')
            return c + 32;

        return c;
    }

    inline size_t strlen(const char* str) {
        const char* s;
        for (s = str; *s; ++s) {}

        return static_cast<size_t>(s - str);
    }

    typedef unsigned short wchar_t;

    inline wchar_t towlower(wchar_t wc) {
        if (wc >= L'A' && wc <= L'Z')
            return wc - L'A' + L'a';

        return wc;
    }

    inline int _wcsicmp(const wchar_t* s1, const wchar_t* s2) {
        wchar_t c1, c2;
        do {
            c1 = towlower(*s1++);
            c2 = towlower(*s2++);

            if (c1 == L'\0')
                break;

        } while (c1 == c2);

        return (int)(c1 - c2);
    }

    inline const char* strstr(const char* haystack, const char* needle) {
        if (*needle == '\0')
            return haystack;

        for (const char* h = haystack; *h != '\0'; ++h) {
            const char* n = needle;
            const char* h2 = h;

            while (*n != '\0' && *h2 != '\0' && *h2 == *n) {
                ++n;
                ++h2;
            }

            if (*n == '\0')
                return h;
        }

        return 0;
    }

    inline char* strrchr(const char* str, int c) {
        char* last_occurrence = 0;
        char ch = (char)c;

        while (*str) {
            if (*str == ch) {
                last_occurrence = (char*)str;
            }
            str++;
        }

        if (ch == '\0') { 
            return (char*)str;
        }

        return last_occurrence;
    }
};