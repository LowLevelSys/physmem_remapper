#pragma once
#include "../struct/dbd_structs.hpp"
#include "../struct/general_structs.hpp"

namespace gutil {
    inline long screen_centerx = 0;
    inline long screen_centery = 0;

	static vmatrix CreateMatrix(vector3 rot, vector3 origin) {
		const float DEG_TO_RAD = static_cast<float>(3.14159265358979323846) / 180.f;
		const float radPitch = rot.x * DEG_TO_RAD;
		const float radYaw = rot.y * DEG_TO_RAD;
		const float radRoll = rot.z * DEG_TO_RAD;

		const float SP = sinf(radPitch);
		const float CP = cosf(radPitch);
		const float SY = sinf(radYaw);
		const float CY = cosf(radYaw);
		const float SR = sinf(radRoll);
		const float CR = cosf(radRoll);

		vmatrix matrix;
		matrix.matrix[0][0] = CP * CY;
		matrix.matrix[0][1] = CP * SY;
		matrix.matrix[0][2] = SP;
		matrix.matrix[0][3] = 0.f;

		matrix.matrix[1][0] = SR * SP * CY - CR * SY;
		matrix.matrix[1][1] = SR * SP * SY + CR * CY;
		matrix.matrix[1][2] = -SR * CP;
		matrix.matrix[1][3] = 0.f;

		matrix.matrix[2][0] = -(CR * SP * CY + SR * SY);
		matrix.matrix[2][1] = CY * SR - CR * SP * SY;
		matrix.matrix[2][2] = CR * CP;
		matrix.matrix[2][3] = 0.f;

		matrix.matrix[3][0] = origin.x;
		matrix.matrix[3][1] = origin.y;
		matrix.matrix[3][2] = origin.z;
		matrix.matrix[3][3] = 1.f;

		return matrix;
	}

	float dot(vector3 left, vector3 right) {
		return (left.x * right.x) + (left.y * right.y) + (left.z * right.z);
	}

    vector2 world_to_screen(FMinimalViewInfo* camera, float real_fov, FVector world_location) {
		if (!screen_centerx || !screen_centery) {
			screen_centerx = GetSystemMetrics(SM_CXSCREEN) / 2;
			screen_centery = GetSystemMetrics(SM_CYSCREEN) / 2;
		}
        vector3 Screenlocation(0, 0, 0);
        vector3 rot = vector3(camera->Rotation.pitch, camera->Rotation.yaw, camera->Rotation.roll);
        vector3 campos = vector3(camera->Location.x, camera->Location.y, camera->Location.z);
		vector3 world = vector3(world_location.x, world_location.y, world_location.z);

        const vmatrix tempMatrix = CreateMatrix(rot, vector3(0, 0, 0));

        vector3 vAxisX(tempMatrix.matrix[0][0], tempMatrix.matrix[0][1], tempMatrix.matrix[0][2]);
        vector3 vAxisY(tempMatrix.matrix[1][0], tempMatrix.matrix[1][1], tempMatrix.matrix[1][2]);
        vector3 vAxisZ(tempMatrix.matrix[2][0], tempMatrix.matrix[2][1], tempMatrix.matrix[2][2]);

        vector3 vDelta = world - campos;

        vector3 vTransformed = vector3(dot(vDelta, vAxisY), dot(vDelta, vAxisZ), dot(vDelta, vAxisX));

        if (vTransformed.z < 1.f)
            vTransformed.z = 1.f;

        const float FOV_DEG_TO_RAD = static_cast<float>(3.14159265358979323846) / 360.f;

		if (real_fov) {
			camera->FOV = real_fov;
		}

        Screenlocation.x = screen_centerx + vTransformed.x * (screen_centerx / tanf(camera->FOV * FOV_DEG_TO_RAD)) / vTransformed.z;
		Screenlocation.y = screen_centery - vTransformed.y * (screen_centerx / tanf(camera->FOV * FOV_DEG_TO_RAD)) / vTransformed.z;

        return vector2(Screenlocation.x, Screenlocation.y);
    }
}