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

		if (entity->IsA(dbd::game_data::agenerator_class))
			return true;

		/*
		if (entity->IsA(dbd::game_data::asearchable_class))
			return true;

		if (entity->IsA(dbd::game_data::aescape_door_class))
			return true;

		if (entity->IsA(dbd::game_data::ahatch_class))
			return true;

		if (entity->IsA(dbd::game_data::apallet_class))
			return true;

		if (entity->IsA(dbd::game_data::awindow_class))
			return true;

		if (entity->IsA(dbd::game_data::atotem_class))
			return true;

		if (entity->IsA(dbd::game_data::abreakable_class))
			return true;

		if (entity->IsA(dbd::game_data::acollectable_class))
			return true;
		*/

		return false;
	}


	inline void draw_entity_esp(void) {
		TArray<ULevel*> world_levels = dbd_mem_util::read_tarray<ULevel*>((void*)((uint64_t)dbd::game_data::uworld + offsetof(UWorld, levels)));

		if (world_levels.Num() == 0) {
			log("No levels found in UWorld");
			return;
		}

		for (int i = 0; i < world_levels.Num(); i++) {
			if (!world_levels.IsValidIndex(i))
				break;

			ULevel* level = world_levels[i];
			if (!level)
				continue;

			TArray<struct AActor*> level_actors = dbd_mem_util::read_tarray<AActor*>((void*)((uint64_t)level + offsetof(ULevel, actors)));

			for (int j = 0; i < level_actors.Num(); j++) {
				if (!level_actors.IsValidIndex(j))
					break;

				AActor* pactor = level_actors[j];
				AActor actor = g_proc->read<AActor>(pactor);

				if (!pactor || !actor.RootComponent)
					continue;

				// Ignore our player
				if (pactor == dbd::game_data::local_player.player_controller)
					continue;

				if (!should_draw_entity(pactor))
					continue;

				std::string entity_name = pactor->GetName();
				USceneComponent curr_scene_component = g_proc->read<USceneComponent>(actor.RootComponent);

				APlayerCameraManager cam = dbd::game_data::camera_manager;
				vector2 root_comp = gutil::world_to_screen(&cam.CameraCachePrivate.pov, cam.DefaultFOV, curr_scene_component.relative_location);
				if (!root_comp.x || !root_comp.y) {
					log("Failed to project world to screen");
					continue;
				}

				overlay::draw_text(root_comp.x, root_comp.y, entity_name.c_str(), IM_COL32(255, 255, 255, 255));
			}

			delete[] level_actors.GetData();
		}

		delete[] world_levels.GetData();
	}
};