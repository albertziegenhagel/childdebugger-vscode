#pragma once

#include <filesystem>
#include <format>
#include <fstream>

#include <vsdebugeng.h>
#include <vsdebugeng.templates.h>

#include "UnicodeUtils.hpp"

enum class LogLevel
{
    off   = 0,
    error = 1,
    info  = 2,
    debug = 3,
    trace = 4
};

class Logger
{
public:
    template<typename... Args>
    HRESULT log(LogLevel                                                                level,
                Microsoft::VisualStudio::Debugger::DefaultPort::DkmTransportConnection* connection,
                std::wformat_string<Args...>                                            fmt,
                Args&&... args);

    void set_log_level(LogLevel level);

    void set_log_file(const std::filesystem::path& file_path);

private:
    LogLevel level_ = LogLevel::error;

    std::ofstream log_file_;
};

void Logger::set_log_level(LogLevel level)
{
    level_ = level;
}

void Logger::set_log_file(const std::filesystem::path& file_path)
{
    log_file_.open(file_path, std::ios::out | std::ios::app);
}

template<typename... Args>
HRESULT Logger::log(LogLevel                                                                level,
                    Microsoft::VisualStudio::Debugger::DefaultPort::DkmTransportConnection* connection,
                    std::wformat_string<Args...>                                            fmt,
                    Args&&... args)
{
    using namespace Microsoft::VisualStudio::Debugger;

    if(std::to_underlying(level) > std::to_underlying(level_)) return S_OK;

    const auto message = std::format(fmt, std::forward<Args>(args)...);

    if(log_file_.is_open())
    {
        log_file_ << utf16_to_utf8(message);
    }

    CComPtr<DkmString> message_str;
    if(DkmString::Create(message.c_str(), &message_str) != S_OK)
    {
        return S_FALSE;
    }

    CComPtr<DkmUserMessage> user_message;
    if(DkmUserMessage::Create(connection, nullptr, DkmUserMessageOutputKind::UnfilteredOutputWindowMessage, message_str, MB_OK, S_OK, &user_message) != S_OK)
    {
        return S_FALSE;
    }

    return user_message->Post();
}
