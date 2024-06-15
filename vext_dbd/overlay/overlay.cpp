#include "overlay.hpp"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace overlay {
    ID3D11Device* g_d3d_device = nullptr;
    ID3D11DeviceContext* g_device_context = nullptr;
    IDXGISwapChain* g_swapchain = nullptr;
    ID3D11RenderTargetView* g_main_render_target_view = nullptr;
    HWND g_hwnd = nullptr;

    LRESULT CALLBACK wnd_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
        if (ImGui_ImplWin32_WndProcHandler(window, message, w_param, l_param))
            return 0;

        if (message == WM_DESTROY) {
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProc(window, message, w_param, l_param);
    }

    void create_render_target() {
        ID3D11Texture2D* back_buffer;

        g_swapchain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
        g_d3d_device->CreateRenderTargetView(back_buffer, nullptr, &g_main_render_target_view);
        back_buffer->Release();
    }

    bool create_d3d_device(HWND hwnd) {
        DXGI_SWAP_CHAIN_DESC sd = { 0 };
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hwnd;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };

        HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_swapchain, &g_d3d_device, &featureLevel, &g_device_context);
        
        if (res == DXGI_ERROR_UNSUPPORTED)
            res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_swapchain, &g_d3d_device, &featureLevel, &g_device_context);
        
        if (res != S_OK)
            return false;

        create_render_target();
        return true;
    }

    void cleanup_render_target() {
        if (g_main_render_target_view)  { 
            g_main_render_target_view->Release(); 
            g_main_render_target_view = nullptr; 
        }
    }

    void cleanup_d3d_device() {
        cleanup_render_target();
        if (g_swapchain) { g_swapchain->Release(); g_swapchain = 0; }
        if (g_device_context) { g_device_context->Release(); g_device_context = 0; }
        if (g_d3d_device) { g_d3d_device->Release(); g_d3d_device = 0; }
    }

    bool init_overlay(void) {
        WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, wnd_proc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"Discord", nullptr };
        ::RegisterClassExW(&wc);

        g_hwnd = ::CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST, wc.lpszClassName, L"Discord", WS_POPUP, 0, 0, 1920, 1080, nullptr, nullptr, wc.hInstance, nullptr);

        SetLayeredWindowAttributes(g_hwnd, RGB(0, 0, 0), 0, ULW_COLORKEY);

        if (!create_d3d_device(g_hwnd)) {
            cleanup_d3d_device();
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
            return false;
        }

        ::ShowWindow(g_hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(g_hwnd);

        MARGINS margins = { -1 };
        DwmExtendFrameIntoClientArea(g_hwnd, &margins);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

        ImGui::StyleColorsDark();

        ImGui_ImplWin32_Init(g_hwnd);
        ImGui_ImplDX11_Init(g_d3d_device, g_device_context);

        return true;
    }

    bool handle_messages(void) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) {
                return false;
            }
        }

        return true;
    }

    void draw_box(float x, float y, float width, float height, ImU32 color, float thickness) {
        ImGui::GetForegroundDrawList()->AddRect(ImVec2(x, y), ImVec2(x + width, y + height), color, 0.0f, 0, thickness);
    }

    void draw_text(float x, float y, const char* text, ImU32 color) {
        ImGui::GetForegroundDrawList()->AddText(ImVec2(x, y), color, text);
    }

    void begin_frame(void) {
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
    }

    void end_frame(void) {
        ImGui::Render();
        g_device_context->OMSetRenderTargets(1, &g_main_render_target_view, nullptr);

        const float clear_color[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        g_device_context->ClearRenderTargetView(g_main_render_target_view, (float*)&clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }

    void render(void) {
        g_swapchain->Present(1, 0);
    }

    void cleanup(void) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        cleanup_d3d_device();

        UnregisterClassW(L"Discord", GetModuleHandle(nullptr));
    }
}
