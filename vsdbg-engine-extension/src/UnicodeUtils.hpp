#pragma once

#include <Windows.h>

#include <cassert>
#include <string>

// Takes the Wide-Char (UTF-16) encoded input string and returns it as an UTF-8 encoded string.
inline std::string utf16_to_utf8(const std::wstring& input)
{
    if(input.empty()) return {};

    const auto result_size = WideCharToMultiByte(CP_UTF8, 0,
                                                 input.data(), static_cast<int>(input.size()),
                                                 nullptr, 0,
                                                 nullptr, nullptr);
    assert(result_size > 0);

    std::string result(result_size, '\0');
    const auto  bytes_converted = WideCharToMultiByte(CP_UTF8, 0,
                                                      input.data(), static_cast<int>(input.size()),
                                                      result.data(), result_size,
                                                      nullptr, nullptr);
    assert(bytes_converted != 0);

    return result;
}

// Takes the UTF-8 encoded input string and returns it as an Wide-Char (UTF-16) encoded string.
inline std::wstring utf8_to_utf16(const std::string& input)
{
    if(input.empty()) return {};

    const auto result_size = MultiByteToWideChar(CP_UTF8, 0,
                                                 input.data(), static_cast<int>(input.size()),
                                                 nullptr, 0);
    assert(result_size > 0);

    std::wstring result(result_size, L'\0');
    const auto   bytes_converted = MultiByteToWideChar(CP_UTF8, 0,
                                                       input.data(), static_cast<int>(input.size()),
                                                       result.data(), result_size);
    assert(bytes_converted != 0);

    return result;
}
