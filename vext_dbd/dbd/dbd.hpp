#pragma once
#include "../driver/driver_um_lib.hpp"
#include "../proc/process.hpp"
#include "struct/dbd_structs.hpp"

namespace dbd {
	inline bool is_inited = false;

	namespace game_data {
		/*
			Core
		*/
		inline bool usable_game_data;

		inline std::vector<AActor*> generators;
		inline uint64_t uworld;
		inline TUObjectArray uobjects;
		inline UWorld uworld_data;
		inline AGameStateBase game_state;
		inline UGameInstance owning_game_instance;
		inline UPlayer local_player;
		inline APlayerController player_controller;
		inline APlayerCameraManager camera_manager;

	};

	namespace settings {
		namespace esp {
			inline bool draw_player_esp = true;

			inline bool draw_name_esp = true;
		};

		namespace misc {
			inline bool auto_skillcheck = true;
			inline bool fov_changer = false;
			inline float fov = 120.f;
		};
	};


	// Initialization
	bool init_cheat(void);
};