#pragma once
#include "../driver/driver_um_lib.hpp"
#include "../proc/process.hpp"
#include "struct/dbd_structs.hpp"
#include <unordered_map>

namespace dbd {
	inline bool is_inited = false;

	static enum COMPARISON_IDS : uint32_t {
		GENERATOR = 0x3b8c4,
		ESCAPE_DOOR = 0x3b442,
		WINDOW = 0x3dff8,
		SEARCHABLE = 0x3d41e,
		TOTEM = 0x3dc02,
		HATCH = 0x3bb20,
		BREAKABLE_BASE = 0x38a00,
		COLLECTABLE = 0x33f2c,
		PALLET = 0x3c980,
	};

	namespace game_data {
		/*
			Core
		*/
		inline bool usable_game_data;

		inline uint64_t uworld;
		inline TUObjectArray uobjects;
		inline std::unordered_map<std::string, UObject*> uobject_cache;
		inline UWorld uworld_data;
		inline AGameStateBase game_state;
		inline UGameInstance owning_game_instance;
		inline UPlayer local_player;
		inline APlayerController player_controller;
		inline APlayerCameraManager camera_manager;

		/*
			UObject Classes
		*/
		inline std::unordered_map<uint32_t, UClass*> objectClasses = {
			{ COMPARISON_IDS::GENERATOR, nullptr },
			{ COMPARISON_IDS::SEARCHABLE, nullptr },
			{ COMPARISON_IDS::TOTEM, nullptr },
			{ COMPARISON_IDS::HATCH, nullptr },
			{ COMPARISON_IDS::PALLET, nullptr },
			{ COMPARISON_IDS::WINDOW, nullptr },
			{ COMPARISON_IDS::COLLECTABLE, nullptr },
			{ COMPARISON_IDS::ESCAPE_DOOR, nullptr },
			{ COMPARISON_IDS::BREAKABLE_BASE, nullptr }
		};

		/*
			Actors of each class
		*/
		inline std::vector<AActor*> generators;
		inline std::vector<AActor*> escape_doors;
		inline std::vector<AActor*> searchables;
		inline std::vector<AActor*> totems;
		inline std::vector<AActor*> hatches;
		inline std::vector<AActor*> pallets;
		inline std::vector<AActor*> windows;
		inline std::vector<AActor*> collectables;
		inline std::vector<AActor*> breakables;

		inline std::vector<AActor*> all;
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