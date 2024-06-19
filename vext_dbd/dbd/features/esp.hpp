#pragma once
#include "../struct/dbd_structs.hpp"
#include "../util/dbd_mem_util.hpp"
#include "../struct/general_structs.hpp"
#include "../util/gutil.hpp"
#include "../../overlay/overlay.hpp"
#include "../dbd.hpp"


namespace dbd_esp {
	static FVector RotateVector(const FVector& vec, const FRotator& rot)
	{
		// Convert the FRotator to a rotation matrix
		double cp = cos(rot.pitch);
		double sp = sin(rot.pitch);
		double cy = cos(rot.yaw);
		double sy = sin(rot.yaw);
		double cr = cos(rot.roll);
		double sr = sin(rot.roll);

		double matrix[3][3] = {
			{ cp * cy, cp * sy, -sp },
			{ sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, sr * cp },
			{ cr * sp * cy + sr * sy, cr * sp * sy - sr * cy, cr * cp }
		};

		// Rotate the vector by the rotation matrix
		FVector rotated_vec;
		rotated_vec.x = vec.x * matrix[0][0] + vec.y * matrix[0][1] + vec.z * matrix[0][2];
		rotated_vec.y = vec.x * matrix[1][0] + vec.y * matrix[1][1] + vec.z * matrix[1][2];
		rotated_vec.z = vec.x * matrix[2][0] + vec.y * matrix[2][1] + vec.z * matrix[2][2];

		return rotated_vec;
	}

	inline void draw_player_esp(void) {
		TArray<APlayerState*> player_state_addresses = dbd_mem_util::read_tarray<APlayerState*>((void*)((uint64_t)dbd::game_data::uworld_data.game_state + offsetof(AGameStateBase, player_array)));

		if (player_state_addresses.Num() == 0) {
			log("No players found in the game state.");
			return;
		}

		for (int i = 0; i < player_state_addresses.Num(); i++) {
			APlayerState curr_player = g_proc->read<APlayerState>((void*)player_state_addresses[i]);

			if (!curr_player.PawnPrivate)
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
			vector2 root_comp = gutil::world_to_screen(cam.CameraCachePrivate.pov, cam.ViewTarget.POV.FOV, curr_scene_component.relative_location);
			if (!root_comp.x || !root_comp.y) {
				log("Failed to project world to screen");
				continue;
			}
			
			overlay::draw_text(root_comp.x, root_comp.y, player_name.c_str(), IM_COL32(255, 255, 255, 255));
		}

		for (AActor* generator : dbd::game_data::generators) {
			AActor generator_instance = g_proc->read<AActor>(generator);
			USceneComponent curr_scene_component = g_proc->read<USceneComponent>((void*)generator_instance.RootComponent);
			APlayerCameraManager cam = dbd::game_data::camera_manager;
			vector2 root_comp = gutil::world_to_screen(cam.CameraCachePrivate.pov, cam.ViewTarget.POV.FOV, curr_scene_component.relative_location);
			if (!root_comp.x || !root_comp.y) {
				log("Failed to project world to screen");
				continue;
			}

			overlay::draw_text(root_comp.x, root_comp.y, "Generator", IM_COL32(255, 255, 255, 255));
		}

		delete[] player_state_addresses.GetData();
	}
};