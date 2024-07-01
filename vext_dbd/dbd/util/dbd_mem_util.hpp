#pragma once
#include "../../driver/driver_um_lib.hpp"
#include "../../proc/process.hpp"
#include "../struct/dbd_structs.hpp"
#include <string>

namespace dbd_mem_util {

    inline std::string read_fstring(void* fstring_address) {
        FString player_name_fstring = g_proc->read<FString>(fstring_address);

        if (player_name_fstring.is_valid() && player_name_fstring.num() > 0) {
            uint64_t name_size = player_name_fstring.num() * sizeof(wchar_t);
            wchar_t* player_name_data = new wchar_t[player_name_fstring.num() + 1];  // +1 for null terminator

            if (!g_proc->read_array(player_name_data, player_name_fstring.get_data(), name_size)) {
                log("Failed to read player name data.");
                delete[] player_name_data;
                return "";
            }

            player_name_data[player_name_fstring.num()] = L'\0';

            std::wstring player_name_wstr(player_name_data);
            delete[] player_name_data;

            std::mbstate_t state = std::mbstate_t();
            const wchar_t* data = player_name_wstr.data();
            size_t len = 1 + std::wcsrtombs(nullptr, &data, 0, &state);

            std::string player_name(len, '\0');
            std::wcsrtombs(&player_name[0], &data, len, &state);
            player_name.resize(len - 1); // Remove the extra null terminator

            return player_name;
        }
        else {
            log("Failed to read player name");
            return "";
        }
    }

    template<typename t>
    TArray<t> read_tarray(void* tarray_address) {
        TArray<t> remote_tarray = g_proc->read<TArray<t>>(tarray_address);
        TArray<t> local_array;

        local_array.Count = remote_tarray.Count;
        local_array.Max = remote_tarray.Max;

        if (!local_array.Count && remote_tarray.Count <= 0) {
            local_array.Count = 0;
            local_array.Max = 0;
            local_array.Data = nullptr;
            return local_array;
        }

        t* content = new t[local_array.Count];

        if (!g_proc->read_array(content, remote_tarray.Data, local_array.Count * sizeof(t))) {
            delete[] content;
            local_array.Count = 0;
            local_array.Max = 0;
            local_array.Data = nullptr;
            return local_array;
        }

        local_array.Data = content;

        return local_array;
    }
};