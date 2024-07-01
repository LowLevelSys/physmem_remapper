#pragma once
#include "../struct/dbd_structs.hpp"
#include "../util/dbd_mem_util.hpp"
#include "../struct/general_structs.hpp"
#include "../util/gutil.hpp"
#include "../../overlay/overlay.hpp"
#include "../dbd.hpp"


namespace player {
	inline void draw_player_esp(void) {
		TArray<APlayerState*> player_state_addresses = dbd_mem_util::read_tarray<APlayerState*>((void*)((uint64_t)dbd::game_data::uworld_data.game_state + offsetof(AGameStateBase, player_array)));
		if (player_state_addresses.num() == 0) {
			log("No players found in the game state.");
			return;
		}

		for (int i = 0; i < player_state_addresses.num(); i++) {
			APlayerState curr_player = g_proc->read<APlayerState>((void*)player_state_addresses[i]);

			if (!curr_player.PawnPrivate)
				continue;

			// Ignore our player
			if ((void*)curr_player.PawnPrivate == dbd::game_data::local_player.player_controller)
				continue;

			APawn curr_pawn = g_proc->read<APawn>((void*)curr_player.PawnPrivate);
			if (!curr_pawn.Instigator)
				continue;

			APawn curr_instigator = g_proc->read<APawn>((void*)curr_pawn.Instigator);
			if (!curr_instigator.RootComponent)
				continue;

			std::string player_name = dbd_mem_util::read_fstring((void*)((uint64_t)player_state_addresses[i] + offsetof(APlayerState, PlayerNamePrivate)));
			USceneComponent curr_scene_component = g_proc->read<USceneComponent>((void*)curr_instigator.RootComponent);
			APlayerCameraManager cam = dbd::game_data::camera_manager;
			FVector* cam_loc = &cam.CameraCachePrivate.pov.Location;

			vector3 cam_pos = { (float)cam_loc->x, (float)cam_loc->y, (float)cam_loc->z };
			vector3 player_pos = { (float)curr_scene_component.relative_location.x, (float)curr_scene_component.relative_location.y, (float)curr_scene_component.relative_location.z };
			float distance = (cam_pos.distTo(player_pos) / 39.62f) - 6;

			if (distance < 0)
				continue;

			std::string dist_string = "-[" + std::to_string((int)distance) + "m]";
			player_name += dist_string;

			vector2 root_comp = gutil::world_to_screen(&cam.CameraCachePrivate.pov, cam.DefaultFOV, curr_scene_component.relative_location);
			if (!root_comp.x || !root_comp.y) {
				log("Failed to project world to screen");
				continue;
			}
			overlay::draw_text(root_comp.x, root_comp.y, player_name.c_str(), IM_COL32(255, 255, 255, 255));

			/*
			TArray<UActorComponent*> actor_comps = dbd_mem_util::read_tarray<UActorComponent*>((void*)((uint64_t)curr_pawn.Instigator + offsetof(AActor, OwnedActorComponents)));
			for (int j = 0; j < actor_comps.num(); j++) {
				std::string component_name = actor_comps[j]->GetName().c_str();

				if (gutil::contains(component_name, "DBDOutline")) {
					//float generator_color[4] = { 0.f, 1.f, 0.f, 0.8f }; // Green
					//g_proc->write_array((void*)((uint64_t)actor_comps[j] + 0x2FC), generator_color, sizeof(generator_color));
					log("%s Outline component at %p", player_name.c_str(), actor_comps[j]);
					continue;
				}
			}
			delete[] actor_comps.get_data();
			*/
		}

		delete[] player_state_addresses.get_data();
	}
};