#pragma once
#include "../project_includes.hpp"
#include "physmem_structs.hpp"

namespace pt_helpers {
    inline bool is_index_valid(uint64_t index) {
        return index < 512;
    }

    inline uint32_t find_free_pml4e_index(pml4e_64* pml4e_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pml4e_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }

    inline uint32_t find_free_pdpt_index(pdpte_64* pdpte_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pdpte_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }

    inline uint32_t find_free_pd_index(pde_64* pde_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pde_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }

    inline uint32_t find_free_pt_index(pte_64* pte_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pte_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }
};

namespace pt_manager {
    // Allocation helpers
    inline pdpte_64* get_free_pdpt_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pdpt_table_occupied[i]) {
                table->is_pdpt_table_occupied[i] = true;
                return table->pdpt_table[i];
            }
        }

        return 0;
    }

    inline pde_64* get_free_pd_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pd_table_occupied[i]) {
                table->is_pd_table_occupied[i] = true;
                return table->pd_table[i];
            }
        }

        return 0;
    }

    inline pte_64* get_free_pt_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pt_table_occupied[i]) {
                table->is_pt_table_occupied[i] = true;
                return table->pt_table[i];
            }
        }

        return 0;
    }

    // Freeing helpers
    inline void safely_free_pdpt_table(constructed_page_tables* table, pdpte_64* pdpt_table) {
        if (!pdpt_table)
            return;

        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (table->pdpt_table[i] == pdpt_table) {
                table->is_pdpt_table_occupied[i] = false;
                crt::memset(pdpt_table, 0, 512 * sizeof(pdpte_64));
                return;
            }
        }
    }

    inline void safely_free_pd_table(constructed_page_tables* table, pde_64* pd_table) {
        if (!pd_table)
            return;

        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (table->pd_table[i] == pd_table) {
                table->is_pd_table_occupied[i] = false;
                crt::memset(pd_table, 0, 512 * sizeof(pde_64));
                return;
            }
        }
    }

    inline void safely_free_pt_table(constructed_page_tables* table, pte_64* pt_table) {
        if (!pt_table)
            return;

        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (table->pt_table[i] == pt_table) {
                table->is_pt_table_occupied[i] = false;
                crt::memset(pt_table, 0, 512 * sizeof(pte_64));
                return;
            }
        }
    }
};