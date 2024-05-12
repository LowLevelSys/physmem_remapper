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
}

namespace pt_manager {
    inline pdpte_64* get_free_pdpt_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pdpt_table_occupied[i]) {
                table->is_pdpt_table_occupied[i] = true;
                return table->pdpt_table[i];
            }
        }

        return 0;
    }

    inline pdpte_1gb_64* get_free_pdpt_1gb_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pdpt_table_occupied[i]) {
                table->is_pdpt_table_occupied[i] = true;
                return table->pdpt_1gb_table[i];
            }
        }

        return 0;
    }

    inline pde_64* get_free_pd_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pd_table_occupied[i]) {
                table->is_pd_table_occupied[i] = true;
                return table->pde_table[i];
            }
        }

        return 0;
    }

    inline pde_2mb_64* get_free_pd_2mb_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pd_table_occupied[i]) {
                table->is_pd_table_occupied[i] = true;
                return table->pde_2mb_table[i];
            }
        }

        return 0;
    }

    inline pte_64* get_free_pt_table(constructed_page_tables* table) {
        for (uint32_t i = 0; i < TABLE_COUNT; i++) {
            if (!table->is_pt_table_occupied[i]) {
                table->is_pt_table_occupied[i] = true;
                return table->pte_table[i];
            }
        }

        return 0;
    }
}