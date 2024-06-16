#include "dbd.hpp"
#include "struct/dbd_structs.hpp"
#include "util/dbd_mem_util.hpp"
#include "features/esp.hpp"
#include "features/auto_skillcheck.hpp"
#include "features/fov_changer.hpp"

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

	//static std::string GetNameById(int32_t actor_id)
	//{
	//	int chunkOffset = (uint32_t)(actor_id >> 16);
	//	uint16_t nameOffset = (uint16_t)actor_id;
	//	uint64_t fNamePool = game_base + dbd::offsets::OFFSET_GNAMES;

	//	uint64_t namePoolChunk = g_proc->read<uint64_t>((void*)(fNamePool + ((chunkOffset + 2) * 8)));
	//	uint64_t entryOffset = namePoolChunk + (uint64_t)(2 * nameOffset);
	//	uint16_t nameEntry = g_proc->read<uint16_t>((void*)entryOffset);
	//	auto nameLength = nameEntry >> 6;
	//	std::string result = g_proc->read_ascii_string(entryOffset + 2, nameLength * 2);
	//	if(!result.empty() || result != "NULL")
	//		return result

	//	//uint64_t TableLocationAddress = g_proc->read<uint64_t>((void*)(GNameTable + 0x10 + static_cast<unsigned long long>(TableLocation) * 0x8)) + (unsigned __int32)(4 * RowLocation);

	//	//uint64_t sLength = (unsigned __int64)(g_proc->read<uint16_t>((void*)(TableLocationAddress + 4))) >> 1;

	//	//if (sLength < 128)
	//	//{
	//	//	return result;
	//	//}

	//	return std::string("NULL");
	//}

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

		// Doesn't seem to work quite properly... wip... seems like we're either not finding the correct generator class, or our comparison isn't correct, OR maybe the generator isn't in the persistent level? it should be though...?
		//UObject* default_generator = game_data::uobjects.FindObject("DeadByDaylight.Generator");
		//UClass* generator_class = g_proc->read<UClass*>(default_generator + offsetof(UObject, Class));

		//ULevel persistent_level = g_proc->read<ULevel>(game_data::uworld_data.persistent_level);
		//uint64_t actor_list = g_proc->read<uint64_t>(persistent_level.actors.Data);
		//for (int i = 0; i < persistent_level.actors.Count; i++) {
		//	AActor* actor = (AActor*)(actor_list + i * 0x8);
		//	AActor actor_instance = g_proc->read<AActor>(actor);

		//	if (actor->IsA(generator_class))
		//		dbd::game_data::generators.push_back(actor);
		//}

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

				if (settings::misc::auto_skillcheck)
					auto_skillcheck::auto_skillcheck();

				if (settings::misc::fov)
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