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

	float length() {
		return sqrt((x * x) + (y * y) + (z * z));
	}

	float length2D() {
		return sqrt((x * x) + (y * y));
	}

	float distTo(vector3 ape) {
		return (*this - ape).length();
	}

	float dist2D(vector3 ape){
		return (*this - ape).length2D();
	}

	float dot(vector3& v) {
		return x * v.x + y * v.y + z * v.z;
	}

	vector3() : x(0.f), y(0.f), z(0.f) {};
	vector3(float x, float y, float z) : x(x), y(y), z(z) {};
};

struct vmatrix {
	vmatrix() {
		for (int i = 0; i < 3; i++)
			for (int j = 0; j < 4; j++)
				m_flMatVal[i][j] = {};
	}
	vmatrix(
		float m00, float m01, float m02, float m03,
		float m10, float m11, float m12, float m13,
		float m20, float m21, float m22, float m23) {
		m_flMatVal[0][0] = m00;	m_flMatVal[0][1] = m01; m_flMatVal[0][2] = m02; m_flMatVal[0][3] = m03;
		m_flMatVal[1][0] = m10;	m_flMatVal[1][1] = m11; m_flMatVal[1][2] = m12; m_flMatVal[1][3] = m13;
		m_flMatVal[2][0] = m20;	m_flMatVal[2][1] = m21; m_flMatVal[2][2] = m22; m_flMatVal[2][3] = m23;
	}

	float* operator[](int i) {
		return m_flMatVal[i];
	}
	const float* operator[](int i) const {
		return m_flMatVal[i];
	}

	float* Base() { return &m_flMatVal[0][0]; }
	const float* Base() const { return &m_flMatVal[0][0]; }

	float m_flMatVal[3][4];
};