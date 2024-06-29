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

		inline uint64_t uworld;
		inline TUObjectArray uobjects;
		inline UWorld uworld_data;
		inline AGameStateBase game_state;
		inline UGameInstance owning_game_instance;
		inline UPlayer local_player;
		inline APlayerController player_controller;
		inline APlayerCameraManager camera_manager;

		inline UObject* agenerator_class;
		inline UObject* aescape_door_class;
		inline UObject* asearchable_class;
		inline UObject* atotem_class;
		inline UObject* ahatch_class;
		inline UObject* apallet_class;
		inline UObject* awindow_class;
		inline UObject* acollectable_class;
		inline UObject* abreakable_class;
	};

	namespace settings {
		namespace esp {
			inline bool draw_player_esp = true;

			inline bool draw_entity_esp = true;

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