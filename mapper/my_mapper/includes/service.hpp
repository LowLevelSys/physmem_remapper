#pragma once
#include <Windows.h>
#include <string>

#include "includes/intel_driver.hpp"

namespace service
{
	bool RegisterAndStart(const std::wstring& driver_path);
	bool StopAndRemove(const std::wstring& driver_name);
};