#include "../driver/driver_um_lib.hpp"
#include "../proc/process.hpp"
#include "struct/dbd_structs.hpp"

#include <thread>

namespace dbd {
	inline bool is_inited = false;
	inline uint64_t game_base = 0;

	namespace offsets {
		// Global
		constexpr auto OFFSET_GWORLD = 0xf34ce80;
	};

	namespace game_data {
		/*
			Core
		*/
		inline bool usable_game_data;

		inline uint64_t uworld;

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
	};


	// Initialization
	bool init_cheat(void);
};