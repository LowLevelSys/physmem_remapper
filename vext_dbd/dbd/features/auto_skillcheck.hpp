#pragma once
#include "../struct/dbd_structs.hpp"
#include "../util/dbd_mem_util.hpp"
#include "../struct/general_structs.hpp"
#include "../util/gutil.hpp"
#include "../../overlay/overlay.hpp"
#include "../dbd.hpp"


namespace auto_skillcheck {

	// We don't have support for doctor auto skillcheck ):
	inline bool is_mirror_skillcheck(float current_progress) {
		return current_progress < 0.f;
	}

	inline void auto_skillcheck(void) {
		TArray<APlayerState*> player_state_addresses = dbd_mem_util::read_tarray<APlayerState*>((void*)((uint64_t)dbd::game_data::uworld_data.game_state + offsetof(AGameStateBase, player_array)));

		if (player_state_addresses.Num() == 0) {
			log("No players found in the game state.");
			return;
		}

		for (int i = 0; i < player_state_addresses.Num(); i++) {
			APlayerState curr_player = g_proc->read<APlayerState>((void*)player_state_addresses[i]);

			if (curr_player.PawnPrivate == dbd::game_data::player_controller.acknowledged_pawn) {
				ADBDPlayer curr_dbd_player = g_proc->read<ADBDPlayer>((void*)curr_player.PawnPrivate);
				UPlayerInteractionHandler interaction_handler = g_proc->read<UPlayerInteractionHandler>((void*)curr_dbd_player.interaction_handler);
				USkillCheck curr_skillcheck = g_proc->read<USkillCheck>((void*)interaction_handler.skillcheck);

				if (!curr_skillcheck.is_displayed)
					break;

				if (is_mirror_skillcheck(curr_skillcheck.current_progress))
					break;

				if (curr_skillcheck.current_progress < curr_skillcheck.success_zone_start)
					break;

				INPUT Input = { 0 };
				Input.type = INPUT_KEYBOARD;
				Input.ki.wVk = VK_SPACE;

				SendInput(1, &Input, sizeof(Input));
				Input.ki.dwFlags = KEYEVENTF_KEYUP;
				SendInput(1, &Input, sizeof(Input));

				break;
			}

		}

		delete[] player_state_addresses.GetData();
	}
};