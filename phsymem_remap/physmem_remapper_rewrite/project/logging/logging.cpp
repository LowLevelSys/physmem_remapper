#include "logging.hpp"
#include <ntstrsafe.h>

namespace logging {
    log_entry_t messages[MAX_MESSAGES] = { 0 };

    uint32_t head_idx = 0;
    uint32_t tail_idx = 0;

    /*
        Utility
    */
    template <typename T>
    char* lukas_itoa(T value, char* result, int base, bool upper = false)
    {
        // check that the base if valid
        if (base < 2 || base > 36) {
            *result = '\0';
            return result;
        }

        char* ptr = result, * ptr1 = result, tmp_char;
        T tmp_value;

        if (upper)
        {
            do
            {
                tmp_value = value;
                value /= base;
                *ptr++ = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    [35 + (tmp_value - value * base)];
            } while (value);
        }
        else
        {
            do
            {
                tmp_value = value;
                value /= base;
                *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"
                    [35 + (tmp_value - value * base)];
            } while (value);
        }

        // Apply negative sign
        if (tmp_value < 0)
            *ptr++ = '-';

        *ptr-- = '\0';
        while (ptr1 < ptr)
        {
            tmp_char = *ptr;
            *ptr-- = *ptr1;
            *ptr1++ = tmp_char;
        }

        return result;
    }

    bool logger_format_copy_str(char* const buffer, char const* const src, uint32_t& idx) {
        for (uint32_t i = 0; src[i]; ++i) {
            buffer[idx++] = src[i];

            // buffer end has been reached
            if (idx >= MAX_MESSAGE_SIZE - 1) {
                buffer[MAX_MESSAGE_SIZE] = '\0';
                return true;
            }
        }

        return false;
    }

    // format a string into a logger buffer, using
    // a limited subset of printf specifiers:
    //   %s, %i, %d, %u, %x, %X, %p
    void logger_format(char* const buffer, char const* const format, va_list& args)
    {
        uint32_t buffer_idx = 0;
        uint32_t format_idx = 0;

        // true if the last character was a '%'
        bool specifying = false;

        while (true) {
            auto const c = format[format_idx++];

            // format end has been reached
            if (c == '\0')
                break;

            if (c == '%') {
                specifying = true;
                continue;
            }

            // just copy the character directly
            if (!specifying) {
                buffer[buffer_idx++] = c;

                // buffer end has been reached
                if (buffer_idx >= MAX_MESSAGE_SIZE - 1)
                    break;

                specifying = false;
                continue;
            }

            char fmt_buffer[128];

            // format the string according to the specifier
            switch (c) {
            case 's': {
                if (logger_format_copy_str(buffer, va_arg(args, char const*), buffer_idx))
                    return;
                break;
            }
            case 'd':
            case 'i': {
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, int), fmt_buffer, 10), buffer_idx))
                    return;
                break;
            }
            case 'u': {
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, unsigned int), fmt_buffer, 10), buffer_idx))
                    return;
                break;
            }
            case 'x': {
                if (logger_format_copy_str(buffer, "0x", buffer_idx))
                    return;
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, unsigned int), fmt_buffer, 16), buffer_idx))
                    return;
                break;
            }
            case 'X': {
                if (logger_format_copy_str(buffer, "0x", buffer_idx))
                    return;
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, unsigned int), fmt_buffer, 16, true), buffer_idx))
                    return;
                break;
            }
            case 'p': {
                if (logger_format_copy_str(buffer, "0x", buffer_idx))
                    return;
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, uint64_t), fmt_buffer, 16, true), buffer_idx))
                    return;
                break;
            }
            }

            specifying = false;
        }

        buffer[buffer_idx] = '\0';
    }

    /*
        Exposed API'S
    */
    void root_printf(const char* fmt, ...) {
        // Check if buffer is full. If it is, then tail needs to move ahead
        if ((head_idx + 1) % MAX_MESSAGES == tail_idx) {
            tail_idx = (tail_idx + 1) % MAX_MESSAGES;
        }

        log_entry_t* curr_entry = &messages[head_idx];
        curr_entry->present = true;

        va_list args;
        va_start(args, fmt);
        logger_format(curr_entry->payload, fmt, args);
        va_end(args);
        head_idx = (head_idx + 1) % MAX_MESSAGES;
    }

    void output_root_logs(log_entry_t* user_message_buffer, uint64_t user_cr3, uint32_t message_count) {
        uint32_t current_idx = tail_idx; // Oldest message
        uint32_t buffer_index = 0;

        while (current_idx != head_idx && buffer_index < message_count) {

            if (physmem::runtime::copy_memory_from_constructed_cr3(
                (void*)&user_message_buffer[buffer_index],  // destination
                (void*)&messages[current_idx],              // source
                sizeof(log_entry_t),
                user_cr3) != status_success) {
                return;
            }
            memset(&messages[buffer_index], 0, sizeof(messages[buffer_index]));

            buffer_index++;
            current_idx = (current_idx + 1) % MAX_MESSAGES;
        }

        tail_idx = head_idx;
    }
    /*
        Initialization
    */
    project_status init_root_logger() {

        memset(messages, 0, sizeof(messages));
        head_idx = 0;
        tail_idx = 0;

        return status_success;
    }
};