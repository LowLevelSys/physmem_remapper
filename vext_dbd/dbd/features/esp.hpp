#pragma once
#include "../struct/dbd_structs.hpp"
#include "../util/dbd_mem_util.hpp"
#include "../struct/general_structs.hpp"
#include "../util/gutil.hpp"
#include "../../overlay/overlay.hpp"

namespace dbd_esp {
	void draw_player_esp(void) {
		TArray<APlayerState*> player_state_addresses = dbd_mem_util::read_tarray<APlayerState*>((void*)((uint64_t)dbd::game_data::uworld_data.game_state + offsetof(AGameStateBase, player_array)));

		if (player_state_addresses.Num() == 0) {
			log("No players found in the game state.");
			return;
		}

		for (int i = 0; i < player_state_addresses.Num(); i++) {
			APlayerState curr_player = g_proc->read<APlayerState>((void*)player_state_addresses[i]);

			if (!curr_player.pawn_private)
				continue;

			APawn curr_pawn = g_proc->read<APawn>((void*)curr_player.pawn_private);
			if (!curr_pawn.instigator)
				continue;

			APawn curr_instigator = g_proc->read<APawn>((void*)curr_pawn.instigator);
			if (!curr_instigator.root_component)
				continue;

			std::string player_name = dbd_mem_util::read_fstring((void*)((uint64_t)player_state_addresses[i] + offsetof(APlayerState, player_name_private)));
			USceneComponent curr_scene_component = g_proc->read<USceneComponent>((void*)curr_instigator.root_component);

			auto cam = dbd::game_data::camera_manager;

			//log("Camera: FOV: %f X: %f Y: %f Z: %f", cam.private_camera_cache.pov.fov, cam.private_camera_cache.pov.location.x, cam.private_camera_cache.pov.location.y, cam.private_camera_cache.pov.location.z);
			
			vector2 root_comp = gutil::world_to_screen(cam.private_camera_cache.pov, curr_scene_component.relative_location);
			if (!root_comp.x || !root_comp.y) {
				log("Failed to project world to screen");
				continue;
			}
			
			overlay::draw_text(root_comp.x, root_comp.y, player_name.c_str(), IM_COL32(255, 255, 255, 255));
		}

		delete[] player_state_addresses.GetData();
	}
};