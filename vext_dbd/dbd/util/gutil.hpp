#pragma once
#include "../struct/dbd_structs.hpp"
#include "../struct/general_structs.hpp"
#include <DirectXMath.h>
using namespace DirectX;

namespace gutil {
    inline long screen_centerx = 0;
    inline long screen_centery = 0;

    using namespace DirectX;

    constexpr double deg_to_rad = static_cast<float>(3.14159265358979323846) / 180.f;


    static vmatrix create_matrix(FRotator rot, vector3 origin = vector3(0,0,0)) {
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
        matrix[0][0] = CP * CY;
        matrix[0][1] = CP * SY;
        matrix[0][2] = SP;
        matrix[0][3] = 0.f;

        matrix[1][0] = SR * SP * CY - CR * SY;
        matrix[1][1] = SR * SP * SY + CR * CY;
        matrix[1][2] = -SR * CP;
        matrix[1][3] = 0.f;

        matrix[2][0] = -(CR * SP * CY + SR * SY);
        matrix[2][1] = CY * SR - CR * SP * SY;
        matrix[2][2] = CR * CP;
        matrix[2][3] = 0.f;

        matrix[3][0] = origin.x;
        matrix[3][1] = origin.y;
        matrix[3][2] = origin.z;
        matrix[3][3] = 1.f;

        return matrix;
    }

    vector2 world_to_screen(FMinimalViewInfo camera, float fov, FVector world_location) {
        // Initialize screen center coordinates if not set
        if (screen_centerx == 0 || screen_centery == 0) {
            screen_centerx = GetSystemMetrics(SM_CXSCREEN) / 2;
            screen_centery = GetSystemMetrics(SM_CYSCREEN) / 2;
        }

        // Create a transformation matrix from the camera rotation
        vmatrix temp_matrix{};
        temp_matrix = create_matrix(camera.Rotation);

        vector3 axis_x(temp_matrix[0][0], temp_matrix[0][1], temp_matrix[0][2]);
        vector3 axis_y(temp_matrix[1][0], temp_matrix[1][1], temp_matrix[1][2]);
        vector3 axis_z(temp_matrix[2][0], temp_matrix[2][1], temp_matrix[2][2]);

        vector3 camera_vec_location(camera.Location.x, camera.Location.y, camera.Location.z);
        vector3 world_vec_location(world_location.x, world_location.y, world_location.z);

        vector3 vdelta = world_vec_location - camera_vec_location;
        vector3 vtransformed(vdelta.dot(axis_y), vdelta.dot(axis_z), vdelta.dot(axis_x));

        // Avoid division by zero
        if (vtransformed.z < 1.0f)
            vtransformed.z = 1.0f;
        
        // Calculate the screen position
        vector2 screen_location(0, 0);
        screen_location.x = screen_centerx + vtransformed.x * (screen_centerx / tanf((fov * 0.5f) * deg_to_rad)) / vtransformed.z;
        screen_location.y = screen_centery - vtransformed.y * (screen_centery / tanf((fov * 0.5f) * deg_to_rad)) / vtransformed.z;

        return screen_location;
    }

    //static XMMATRIX create_matrix(FRotator rot, vector3 origin) {
    //    constexpr float deg_to_rad = DirectX::XM_PI / 180.f;

    //    float rad_pitch = rot.pitch * deg_to_rad;
    //    float rad_yaw = rot.yaw * deg_to_rad;
    //    float rad_roll = rot.roll * deg_to_rad;

    //    log("[yaw, pitch, roll] = [%.3f, %.3f, %.3f]", rad_yaw, rad_pitch, rad_roll);

    //    // Create rotation matrices for pitch, yaw, and roll
    //    DirectX::XMMATRIX rotationMatrix = XMMatrixRotationRollPitchYaw(rad_pitch, rad_yaw, rad_roll);

    //    // Set the translation part of the matrix
    //    rotationMatrix.r[3] = DirectX::XMVectorSet(origin.x, origin.y, origin.z, 1.f);

    //    return rotationMatrix;
    //}

    //vector2 world_to_screen(FMinimalViewInfo camera, float fov, FVector world_location) {
    //    // Initialize screen center coordinates if not set
    //    if (screen_centerx == 0 || screen_centery == 0) {
    //        screen_centerx = GetSystemMetrics(SM_CXSCREEN) / 2;
    //        screen_centery = GetSystemMetrics(SM_CYSCREEN) / 2;
    //    }

    //    // Create a transformation matrix from the camera rotation
    //    DirectX::XMMATRIX rotation_matrix = create_matrix(camera.Rotation, vector3(0, 0, 0));

    //    DirectX::XMVECTOR axis_x = rotation_matrix.r[0];
    //    DirectX::XMVECTOR axis_y = rotation_matrix.r[1];
    //    DirectX::XMVECTOR axis_z = rotation_matrix.r[2];

    //    log("axis_x: %.3f %.3f %.3f", DirectX::XMVectorGetX(axis_x), DirectX::XMVectorGetY(axis_x), DirectX::XMVectorGetZ(axis_x));
    //    log("axis_y: %.3f %.3f %.3f", DirectX::XMVectorGetX(axis_y), DirectX::XMVectorGetY(axis_y), DirectX::XMVectorGetZ(axis_y));
    //    log("axis_z: %.3f %.3f %.3f", DirectX::XMVectorGetX(axis_z), DirectX::XMVectorGetY(axis_z), DirectX::XMVectorGetZ(axis_z));

    //    DirectX::XMVECTOR camera_vec_location = DirectX::XMVectorSet(camera.Location.x, camera.Location.y, camera.Location.z, 0.f);
    //    DirectX::XMVECTOR world_vec_location = DirectX::XMVectorSet(world_location.x, world_location.y, world_location.z, 0.f);
    //    
    //    log("camera_vec_location: %.3f %.3f %.3f", DirectX::XMVectorGetX(camera_vec_location), DirectX::XMVectorGetY(camera_vec_location), DirectX::XMVectorGetZ(camera_vec_location));
    //    log("world_vec_location: %.3f %.3f %.3f", DirectX::XMVectorGetX(world_vec_location), DirectX::XMVectorGetY(world_vec_location), DirectX::XMVectorGetZ(world_vec_location));

    //    DirectX::XMVECTOR vdelta = DirectX::XMVectorSubtract(world_vec_location, camera_vec_location);
    //    DirectX::XMVECTOR vtransformed = DirectX::XMVector3Transform(vdelta, rotation_matrix);
    //    log("vdelta: %.3f %.3f %.3f", DirectX::XMVectorGetX(vdelta), DirectX::XMVectorGetY(vdelta), DirectX::XMVectorGetZ(vdelta));
    //    //DirectX::XMVECTOR vtransformed = DirectX::XMVectorSet(DirectX::XMVectorGetX(DirectX::XMVector3Dot(vdelta, axis_x)), DirectX::XMVectorGetX(DirectX::XMVector3Dot(vdelta, axis_y)), DirectX::XMVectorGetX(DirectX::XMVector3Dot(vdelta, axis_z)), 0.f);
    //    log("vtransformed: %.3f %.3f %.3f", DirectX::XMVectorGetX(vtransformed), DirectX::XMVectorGetY(vtransformed), DirectX::XMVectorGetZ(vtransformed));

    //    // Avoid division by zero
    //    if (DirectX::XMVectorGetZ(vtransformed) < 0.00068f)
    //        vtransformed = DirectX::XMVectorSetZ(vtransformed, 0.00068f);

    //    const float deg_to_rad = DirectX::XM_PI / 180.f;

    //    // Calculate the screen position
    //    vector2 screen_location(0, 0);
    //    screen_location.x = screen_centerx + DirectX::XMVectorGetX(vtransformed) * (screen_centerx / tanf((fov / 2) * deg_to_rad)) / DirectX::XMVectorGetZ(vtransformed);
    //    screen_location.y = screen_centery - DirectX::XMVectorGetY(vtransformed) * (screen_centery / tanf((fov / 2) * deg_to_rad)) / DirectX::XMVectorGetZ(vtransformed);
    //    log("X: %f Y: %f", screen_location.x, screen_location.y);

    //    return screen_location;
    //}
}