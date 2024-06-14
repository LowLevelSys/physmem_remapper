#include <Windows.h>
#include <d3d11.h>
#include <dwmapi.h>

#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/imgui_impl_win32.h"

namespace overlay {
	// Core functions
	void begin_frame(void);
	void end_frame(void);
	void render(void);
	bool handle_messages(void);
	void cleanup(void);

	// Utility drawing functions
	void draw_box(float x, float y, float width, float height, ImU32 color, float thickness);
	void draw_text(float x, float y, const char* text, ImU32 color);

	// Initialization
	bool init_overlay(void);
};