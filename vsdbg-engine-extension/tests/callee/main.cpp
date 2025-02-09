
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct Options
{
    std::chrono::seconds sleep_time = std::chrono::seconds(15);
};

std::string utf16_to_utf8(const std::wstring& input)
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

void print_usage()
{
    std::wcout << L"Usage: callee.exe <Options>\n"
               << L"\n"
               << L"Options:\n"
               << L"  --help, -h        Show this help text.\n"
               << L"  --sleep-time <MS> Time to wait before terminating the app.\n"
               << L"                    default: 15'000\n";
}

[[noreturn]] void print_usage_and_exit(int exit_code)
{
    print_usage();
    std::quick_exit(exit_code);
}

[[noreturn]] void print_error_and_exit(std::wstring_view error)
{
    std::wcout << L"Error:\n"
               << L"  " << error << L"\n\n";
    print_usage_and_exit(EXIT_FAILURE);
}

Options parse_command_line(int argc, wchar_t* argv[]) // NOLINT(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
{
    Options result;
    bool    help = false;
    for(int arg_i = 1; arg_i < argc; ++arg_i)
    {
        const auto current_arg = std::wstring_view(argv[arg_i]);
        if(current_arg == L"--help")
        {
            help = true;
        }
        else if(current_arg == L"--sleep-time")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --sleep-time.");
            const auto next_arg = utf16_to_utf8(argv[++arg_i]);

            std::chrono::milliseconds::rep mills;

            auto chars_result = std::from_chars(next_arg.data(), next_arg.data() + next_arg.size(), mills);
            if(chars_result.ec != std::errc{}) print_error_and_exit(L"Invalid argument for --sleep-time.");

            result.sleep_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(mills));
        }
    }

    if(help)
    {
        print_usage_and_exit(EXIT_SUCCESS);
    }

    return result;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
int wmain(int argc, wchar_t* argv[])
{
    const auto opts = parse_command_line(argc, argv);

    const auto pid = GetCurrentProcessId();
    const auto tid = GetCurrentThreadId();

    std::wcout << L"  CALLEE (" << pid << L", " << tid << L"): initialized" << std::endl;

    std::this_thread::sleep_for(opts.sleep_time);

    std::wcout << L"  CALLEE (" << pid << L", " << tid << L"): terminating" << std::endl;

    return EXIT_SUCCESS;
}
