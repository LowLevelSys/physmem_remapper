#pragma once
#include "../struct/dbd_structs.hpp"
#include "../struct/general_structs.hpp"

namespace gutil {
    inline long screen_centerx = 0;
    inline long screen_centery = 0;

    static vmatrix create_matrix(FRotator rot, vector3 origin) {
        constexpr double deg_to_rad = static_cast<float>(3.14159265358979323846) / 180.f;

        double rad_pitch = rot.pitch * deg_to_rad;
        double rad_yaw = rot.yaw * deg_to_rad;
        double rad_roll = rot.roll * deg_to_rad;

        double SP = sinf((float)rad_pitch);
        double CP = cosf((float)rad_pitch);
        double SY = sinf((float)rad_yaw);
        double CY = cosf((float)rad_yaw);
        double SR = sinf((float)rad_roll);
        double CR = cosf((float)rad_roll);

        vmatrix matrix;

        matrix[0][0] = (float)CP * (float)CY;
        matrix[0][1] = (float)CP * (float)SY;
        matrix[0][2] = (float)SP;
        matrix[0][3] = 0.f;

        matrix[1][0] = (float)SR * (float)SP * (float)CY - (float)CR * (float)SY;
        matrix[1][1] = (float)SR * (float)SP * (float)SY + (float)CR * (float)CY;
        matrix[1][2] = -(float)SR * (float)CP;
        matrix[1][3] = 0.f;

        matrix[2][0] = -((float)CR * (float)SP * (float)CY + (float)SR * (float)SY);
        matrix[2][1] = (float)CY * (float)SR - (float)CR * (float)SP * (float)SY;
        matrix[2][2] = (float)CR * (float)CP;
        matrix[2][3] = 0.f;

        matrix[3][0] = origin.x;
        matrix[3][1] = origin.y;
        matrix[3][2] = origin.z;
        matrix[3][3] = 1.f;

        return matrix;
    }

    vector2 world_to_screen(FMinimalViewInfo camera, float real_fov, FVector world_location) {
        // Initialize screen center coordinates if not set
        if (screen_centerx == 0 || screen_centery == 0) {
            screen_centerx = GetSystemMetrics(SM_CXSCREEN) / 2;
            screen_centery = GetSystemMetrics(SM_CYSCREEN) / 2;
        }

        // Create a transformation matrix from the camera rotation
        vmatrix temp_matrix{};
        temp_matrix = create_matrix(camera.Rotation, vector3());

        vector3 axis_x(temp_matrix[0][0], temp_matrix[0][1], temp_matrix[0][2]);
        vector3 axis_y(temp_matrix[1][0], temp_matrix[1][1], temp_matrix[1][2]);
        vector3 axis_z(temp_matrix[2][0], temp_matrix[2][1], temp_matrix[2][2]);

        vector3 camera_vec_location((float)camera.Location.x, (float)camera.Location.y, (float)camera.Location.z);
        vector3 world_vec_location((float)world_location.x, (float)world_location.y, (float)world_location.z);

        vector3 vdelta = world_vec_location - camera_vec_location;
        vector3 vtransformed(vdelta.dot(axis_y), vdelta.dot(axis_z), vdelta.dot(axis_x));

        // Avoid division by zero
        if (vtransformed.z < 1.0f)
            vtransformed.z = 1.0f;
        

        const float deg_to_rad = static_cast<float>(3.14159265358979323846) / 360.0f;

        // Calculate the screen position
        vector2 screen_location(0, 0);
        screen_location.x = screen_centerx + vtransformed.x * (screen_centerx / tanf(real_fov * deg_to_rad)) / vtransformed.z;
        screen_location.y = screen_centery - vtransformed.y * (screen_centery / tanf(real_fov * deg_to_rad)) / vtransformed.z;

        return screen_location;
    }
}