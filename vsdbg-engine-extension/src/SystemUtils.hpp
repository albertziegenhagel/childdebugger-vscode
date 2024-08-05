#pragma once

#include <Windows.h>

#include <array>
#include <filesystem>
#include <optional>
#include <string>

// Retrieve the path to the module (DLL) that holds this function.
inline std::optional<std::filesystem::path> get_current_module_path()
{
    HMODULE           current_module          = nullptr;
    const auto* const module_function_address = (LPCWSTR)(&get_current_module_path); // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
    if(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, module_function_address, &current_module) == FALSE) return std::nullopt;

    std::array<WCHAR, MAX_PATH> buffer; // FIXME: handle paths longer than MAX_PATH

    const auto result_size = GetModuleFileNameW(current_module, buffer.data(), buffer.size());
    if(result_size == 0) return std::nullopt;

    auto result = std::filesystem::path(buffer.data()).parent_path();
    if(result.empty()) return std::nullopt;

    return result;
}
