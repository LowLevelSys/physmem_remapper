#pragma once


namespace crt {
    inline void* memset(void* src, int val, unsigned __int64 count) {
        typedef unsigned char      uint8_t;
        uint8_t* byte_src = reinterpret_cast<uint8_t*>(src);

        for (unsigned __int64 i = 0; i < count; ++i)
            byte_src[i] = static_cast<uint8_t>(val);

        return src;
    }

    inline void* memmove(void* dest, const void* src, unsigned __int64 count) {
        char* char_dest = (char*)dest;
        char* char_src = (char*)src;
        if ((char_dest <= char_src) || (char_dest >= (char_src + count))) {
            while (count > 0) {
                *char_dest = *char_src;
                char_dest++;
                char_src++;
                count--;
            }
        }
        else {
            char_dest = (char*)dest + count - 1;
            char_src = (char*)src + count - 1;
            while (count > 0) {
                *char_dest = *char_src;
                char_dest--;
                char_src--;
                count--;
            }
        }
        return dest;
    }

    inline int memcmp(const void* s1, const void* s2, unsigned __int64 n)
    {
        if (n != 0) {
            const unsigned char* p1 = (unsigned char*)s1, * p2 = (unsigned char*)s2;
            do {
                if (*p1++ != *p2++) 
                    return (*--p1 - *--p2);
            } while (--n != 0);
        }
        return 0;
    }

    inline void* memcpy(void* dest, const void* src, unsigned __int64 count)
    {
        char* char_dest = (char*)dest;
        char* char_src = (char*)src;
        if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
        {
            while (count > 0)
            {
                *char_dest = *char_src;
                char_dest++;
                char_src++;
                count--;
            }
        }
        else
        {
            char_dest = (char*)dest + count - 1;
            char_src = (char*)src + count - 1;
            while (count > 0)
            {
                *char_dest = *char_src;
                char_dest--;
                char_src--;
                count--;
            }
        }
        return dest;
    }

    inline int strcmp(const char* cs, const char* ct)
    {
        if (cs && ct)
        {
            while (*cs == *ct)
            {
                if (*cs == 0 && *ct == 0) return 0;
                if (*cs == 0 || *ct == 0) break;
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
                // If we hit a null terminator in either string, stop.
                return (unsigned char)s1[i] - (unsigned char)s2[i];
            }
            if (s1[i] != s2[i]) {
                // If the current characters differ, return the difference.
                return (unsigned char)s1[i] - (unsigned char)s2[i];
            }
        }

        return 0;
    }

    inline char tolower(char c) {
        // Check if the character is uppercase (A-Z)
        if (c >= 'A' && c <= 'Z')
            return c + 32;  // Convert to lowercase

        return c;  // Return the character unchanged if it's not uppercase
    }

    inline size_t strlen(const char* str) {
        const char* s;
        for (s = str; *s; ++s) {}
        return static_cast<size_t>(s - str);
    }

    typedef unsigned short wchar_t;

    inline wchar_t towlower(wchar_t wc) {
        if (wc >= L'A' && wc <= L'Z') {
            return wc - L'A' + L'a';
        }
        return wc;
    }

    inline int _wcsicmp(const wchar_t* s1, const wchar_t* s2) {
        wchar_t c1, c2;
        do {
            c1 = towlower(*s1++);
            c2 = towlower(*s2++);
            if (c1 == L'\0') {
                break;
            }
        } while (c1 == c2);

        return (int)(c1 - c2);
    }

    inline const char* strstr(const char* haystack, const char* needle) {
        if (*needle == '\0')
            return haystack;

        for (const char* h = haystack; *h != '\0'; ++h) {
            // For each position in haystack, check if the needle matches
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
};