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
		ADBDPlayer curr_dbd_player = g_proc->read<ADBDPlayer>((void*)dbd::game_data::player_controller.acknowledged_pawn);
		UPlayerInteractionHandler interaction_handler = g_proc->read<UPlayerInteractionHandler>((void*)curr_dbd_player.interaction_handler);
		USkillCheck curr_skillcheck = g_proc->read<USkillCheck>((void*)interaction_handler.skillcheck);

		if (!curr_skillcheck.is_displayed)
			return;

		if (is_mirror_skillcheck(curr_skillcheck.current_progress))
			return;

		if (curr_skillcheck.current_progress < curr_skillcheck.success_zone_start)
			return;

		INPUT Input = { 0 };
		Input.type = INPUT_KEYBOARD;
		Input.ki.wVk = VK_SPACE;

		SendInput(1, &Input, sizeof(Input));
		Input.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &Input, sizeof(Input));
	}
};