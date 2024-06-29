#pragma once
#include <cmath>

struct vector2 {
	float x, y;
	vector2 operator-(vector2 ape) {
		return { x - ape.x, y - ape.y};
	}

	vector2 operator+(vector2 ape) {
		return { x + ape.x, y + ape.y};
	}

	vector2 operator*(float ape) {
		return { x * ape, y * ape};
	}

	vector2 operator/(float ape) {
		return { x / ape, y / ape};
	}

	vector2 operator/=(float ape) {
		x /= ape;
		y /= ape;

		return *this;
	}

	vector2 operator+=(vector2 ape) {
		return { x += ape.x, y += ape.y};
	}

	vector2 operator-=(vector2 ape) {
		return { x -= ape.x, y -= ape.y};
	}

	float length() {
		return sqrt((x * x) + (y * y));
	}

	float length2D() {
		return sqrt((x * x) + (y * y));
	}

	float distTo(vector2 ape) {
		return (*this - ape).length();
	}

	float dist2D(vector2 ape) {
		return (*this - ape).length2D();
	}

	float dot(vector2& v) {
		return x * v.x + y * v.y;
	}
};

struct vector3 {
	float x, y, z;

	vector3 operator-(vector3 ape) {
		return { x - ape.x, y - ape.y, z - ape.z };
	}

	vector3 operator+(vector3 ape) {
		return { x + ape.x, y + ape.y, z + ape.z };
	}

	vector3 operator*(float ape) {
		return { x * ape, y * ape, z * ape };
	}

	vector3 operator/(float ape) {
		return { x / ape, y / ape, z / ape };
	}

	vector3 operator/=(float ape) {
		x /= ape;
		y /= ape;
		z /= ape;

		return *this;
	}

	vector3 operator+=(vector3 ape) {
		return { x += ape.x, y += ape.y, z += ape.z };
	}

	vector3 operator-=(vector3 ape) {
		return { x -= ape.x, y -= ape.y, z -= ape.z };
	}

	float length() const {
		return sqrt((x * x) + (y * y) + (z * z));
	}

	float length2D() const {
		return sqrt((x * x) + (y * y));
	}

	float distTo(vector3 ape) {
		return (*this - ape).length();
	}

	float dist2D(vector3 ape) {
		return (*this - ape).length2D();
	}

	float dot(vector3& v) const {
		return x * v.x + y * v.y + z * v.z;
	}

	float normalize() {
		float length = this->length();
		if (!length)
			this->x = this->y = this->z = 1.f;
		else {
			this->x /= length;
			this->y /= length;
			this->z /= length;
		}
	}

	vector3() : x(0.f), y(0.f), z(0.f) {};
	vector3(float x, float y, float z) : x(x), y(y), z(z) {};
};

struct vmatrix
{
public:
	float matrix[4][4];

	vector3 transform(const vector3 vector) const
	{
		vector3 transformed;

		transformed.x = vector.y * matrix[0][1] + vector.x * matrix[0][0] + vector.z * matrix[0][2] + matrix[0][3];
		transformed.y = vector.y * matrix[1][1] + vector.x * matrix[1][0] + vector.z * matrix[1][2] + matrix[1][3];
		transformed.z = vector.y * matrix[3][1] + vector.x * matrix[3][0] + vector.z * matrix[3][2] + matrix[3][3];

		return transformed;
	}
};