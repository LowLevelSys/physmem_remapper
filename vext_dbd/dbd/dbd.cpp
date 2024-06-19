#include "dbd.hpp"
#include "struct/dbd_structs.hpp"
#include "util/dbd_mem_util.hpp"
#include "features/esp.hpp"
#include "features/auto_skillcheck.hpp"
#include "features/fov_changer.hpp"

#include "../overlay/overlay.hpp"

std::once_flag obtainedObjectClasses;

namespace dbd {

	/*
		Main cheat
	*/
	bool validate_game_data(void) {
		game_data::usable_game_data = true;

		if (!game_data::uworld) {
			game_data::usable_game_data = false;
		}

		if (!game_data::uworld_data.game_state) {
			game_data::usable_game_data = false;
		}

		return game_data::usable_game_data;
	}

	static std::vector<UObject*> uobjects;

	// This is complete cancer, I'm sorry... lol...

	static void clear_game_data() {
		game_data::generators.clear();
		game_data::searchables.clear();
		game_data::totems.clear();
		game_data::hatches.clear();
		game_data::pallets.clear();
		game_data::windows.clear();
		game_data::collectables.clear();
		game_data::breakables.clear();
	}

	static void initialize_object_classes() {
		uobjects = game_data::uobjects.GetAllObjects();
		for (auto& cls : game_data::objectClasses) {
			for (auto& object : uobjects) {
				if (!object || object->GetComparisonIndex() != cls.first) continue;
				cls.second = (UClass*)object;
				break;
			}
		}
	}

	static void update_actor_classes(AActor* actor) {
		if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::GENERATOR]))
			game_data::generators.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::SEARCHABLE]))
			game_data::searchables.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::TOTEM]))
			game_data::totems.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::HATCH]))
			game_data::hatches.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::PALLET]))
			game_data::pallets.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::WINDOW]))
			game_data::windows.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::COLLECTABLE]))
			game_data::collectables.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::ESCAPE_DOOR]))
			game_data::escape_doors.push_back(actor);
		else if (actor->IsA(game_data::objectClasses[COMPARISON_IDS::BREAKABLE_BASE]))
			game_data::breakables.push_back(actor);

		game_data::all.push_back(actor);
	}

	static void update_objects() {
		if (!game_data::uworld_data.persistent_level)
			clear_game_data();

		std::call_once(obtainedObjectClasses, initialize_object_classes);

		ULevel level_instance = g_proc->read<ULevel>(game_data::uworld_data.persistent_level);

		std::vector<AActor*> actors(level_instance.actors.Count);
		g_proc->read_array(actors.data(), (void*)(uint64_t(level_instance.actors.Data)), static_cast<uint64_t>(level_instance.actors.Count * sizeof(AActor*)));

		for (auto& actor : actors) {
			if (!actor || std::find(game_data::all.begin(), game_data::all.end(), actor) != game_data::all.end()) continue;
			update_actor_classes(actor);
		}
	}

	struct vInt {
		int x;
		int y;
	};

	bool update_base_game_data(void) {
		if (!game_base)
			return false;

		game_data::uworld = g_proc->read<uint64_t>((void*)(game_base + offsets::OFFSET_GWORLD));
		if (!game_data::uworld)
			return false;
		
		game_data::uworld_data = g_proc->read<UWorld>((void*)game_data::uworld);
		if (!game_data::uworld_data.game_state)
			return false;

		game_data::game_state = g_proc->read<AGameStateBase>((void*)(game_data::uworld_data.game_state));
		if (!game_data::game_state.player_array.Data || game_data::game_state.player_array.Count <= 0) 
			return false;

		game_data::owning_game_instance = g_proc->read<UGameInstance>((void*)game_data::uworld_data.owning_game_instance);
		if (!game_data::owning_game_instance.local_players.Data || game_data::owning_game_instance.local_players.Count <= 0)
			return false;

		TArray<UPlayer*> local_players = g_proc->read<TArray<UPlayer*>>((void*)((uint64_t)game_data::uworld_data.owning_game_instance + offsetof(UGameInstance, local_players)));
		if (!local_players.Data || local_players.Count <= 0)
			return false;

		game_data::local_player = g_proc->read<UPlayer>((void*)g_proc->read<uint64_t>(local_players.Data)); // We are the first entry in local_players
		if (!game_data::local_player.player_controller)
			return false;

		game_data::player_controller = g_proc->read<APlayerController>((void*)game_data::local_player.player_controller);
		if (!game_data::player_controller.camera_manager)
			return false;

		game_data::uobjects = g_proc->read<TUObjectArray>((void*)(game_base + offsets::OFFSET_GOBJECTS));
		//game_data::uobjects.Log(); // Debug print all object names...
		
		// The below is just all super cancerous, but it works for now.
		update_objects();

		game_data::camera_manager = g_proc->read<APlayerCameraManager>((void*)game_data::player_controller.camera_manager);

		return true;
	}

	void cheat_loop(void) {

		bool done = false;

		// Continously execute the cheat loop
		while (!done) {
			if (!overlay::handle_messages()) {
				done = true;
				break;
			}

			// Update and validate game data
			update_base_game_data();
			if (!validate_game_data()) {
				Sleep(10);
				continue;
			}

			if (settings::misc::auto_skillcheck)
					auto_skillcheck::auto_skillcheck();

			overlay::begin_frame(); {
				if (settings::esp::draw_player_esp)
					dbd_esp::draw_player_esp();

				if (settings::misc::fov_changer)
					fov_changer::set_fov(settings::misc::fov);
			}
			overlay::end_frame();
			overlay::render();

			Sleep(10);
		}

		overlay::cleanup();
	}


	/*
		Initialization
	*/
	bool init_cheat(void) {
		g_proc = process_t::get_inst("DeadByDaylight-Win64-Shipping.exe");
		if (!g_proc)
			return false;

		game_base = g_proc->get_module_base("DeadByDaylight-Win64-Shipping.exe");
		if (!game_base) {
			log("Failed to get game base");
			return false;
		}

		if (!overlay::init_overlay()) {
			log("Failed to init overlay");
			return false;
		}

		is_inited = true;

		cheat_loop();

		return true;
	}

};