#pragma once
#include "../struct/dbd_structs.hpp"
#include "../util/dbd_mem_util.hpp"
#include "../struct/general_structs.hpp"
#include "../util/gutil.hpp"
#include "../../overlay/overlay.hpp"
#include "../dbd.hpp"

namespace fov_changer {
	
	void set_fov(float new_fov) {
		uint64_t camera_manager = (uint64_t)dbd::game_data::player_controller.camera_manager;

		g_proc->write((void*)(camera_manager + offsetof(APlayerCameraManager, locked_fov)), new_fov);
	}
};