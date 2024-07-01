#pragma once
#include "../struct/dbd_structs.hpp"
#include "../util/dbd_mem_util.hpp"
#include "../struct/general_structs.hpp"
#include "../util/gutil.hpp"
#include "../../overlay/overlay.hpp"
#include "../dbd.hpp"

namespace entity {

	inline bool should_draw_entity(AActor* entity) {
		if (!entity)
			return false;

		return false;
	}


	inline void draw_entity_esp(void) {
		for (AActor* Actor : dbd::game_data::cached_actors) {
			if (!should_draw_entity(Actor))
				continue;
		}
	}
};