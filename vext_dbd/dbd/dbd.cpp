#include "dbd.hpp"
#include "struct/dbd_structs.hpp"
#include "util/dbd_mem_util.hpp"

#include "features/player.hpp"
#include "features/auto_skillcheck.hpp"
#include "features/fov_changer.hpp"
#include "features/entitiy.hpp"

#include "../overlay/overlay.hpp"

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

	void update_actor_caches(void) {
		TArray<ULevel*> world_levels = dbd_mem_util::read_tarray<ULevel*>((void*)((uint64_t)dbd::game_data::uworld + offsetof(UWorld, levels)));
		if (world_levels.num() == 0) {
			log("No levels found in UWorld");
			return;
		}

		std::unordered_set<AActor*> curr_actors;
		for (int i = 0; i < world_levels.num(); i++) {
			if (!world_levels[i])
				continue;

			TArray<AActor*> level_actors = dbd_mem_util::read_tarray<AActor*>((void*)((uint64_t)world_levels[i] + offsetof(ULevel, actors)));
			for (int j = 0; j < level_actors.num(); j++) {
				if (!level_actors[i])
					continue;

				curr_actors.insert(level_actors[j]);
			}
		}

		for (auto it = game_data::cached_actors.begin(); it != game_data::cached_actors.end();) {
			if (curr_actors.find(*it) == curr_actors.end()) {
				it = game_data::cached_actors.erase(it);
			}
			else {
				++it;
			}
		}

		for (AActor* actor : curr_actors) {
			game_data::cached_actors.insert(actor);
		}
	}

	bool update_base_game_data(void) {
		if (!game_base)
			return false;

		/*
			Update game base info
		*/

		game_data::uworld = g_proc->read<uint64_t>((void*)(game_base + offsets::OFFSET_GWORLD));
		if (!game_data::uworld)
			return false;

		game_data::uobjects = g_proc->read<TUObjectArray>((void*)(game_base + offsets::OFFSET_GOBJECTS));
		if (!game_data::uobjects.num())
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

		game_data::camera_manager = g_proc->read<APlayerCameraManager>((void*)game_data::player_controller.camera_manager);

		update_actor_caches();

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
				continue;
			}

			if (settings::misc::auto_skillcheck)
				auto_skillcheck::auto_skillcheck();

			overlay::begin_frame(); {
				if (settings::esp::draw_player_esp)
					player::draw_player_esp();

				/*
				if (settings::esp::draw_entity_esp)
					entity::draw_entity_esp();
				*/

				if (settings::misc::fov_changer)
					fov_changer::set_fov(settings::misc::fov);
			}
			overlay::end_frame();
			overlay::render();
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