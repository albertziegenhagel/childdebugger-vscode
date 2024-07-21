
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct Options
{
    std::filesystem::path     child_path;
    std::vector<std::wstring> child_args;

    bool suspend     = false;
    bool wait        = false;
    bool no_app_name = false;

    std::chrono::seconds init_sleep_time    = std::chrono::seconds(1);
    std::chrono::seconds suspend_sleep_time = std::chrono::seconds(30);
    std::chrono::seconds final_sleep_time   = std::chrono::seconds(10);
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
    std::wcout << L"Usage: caller.exe <Options> <Path> [- <Child Args>]\n"
               << L"\n"
               << L"Path:\n"
               << L"  Path to the executable to be started as child process.\n"
               << L"Options:\n"
               << L"  --help, -h       Show this help text.\n"
               << L"  --suspend        Create the child process in suspended stat,\n"
               << L"                   wait for a few seconds, and then resume it.\n"
               << L"  --wait           Wait for the child process to terminate.\n"
               << L"  --no-app-name    Pass NULL to lpApplicationName and use\n"
               << L"                   lpCommandLine instead.\n"
               << L"  --init-time <MS>\n"
               << L"                   Time to wait for before starting the child\n"
               << L"                   process. In milliseconds.\n"
               << L"                   default: 1'000\n"
               << L"  --suspend-time <MS>\n"
               << L"                   Time to wait after starting the suspended\n"
               << L"                   process, before resuming it (only when\n"
               << L"                   --suspend). In milliseconds.\n"
               << L"                   default: 30'000\n"
               << L"  --final-time <MS>\n"
               << L"                   Time to wait before terminating the app after\n"
               << L"                   the child process was started. In milliseconds.\n"
               << L"                   default: 10'000\n"
               << L"Child Args:\n"
               << L"  Any additionally arguments beyond the '-' will be passed to\n"
               << L"  to the child process.\n";
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
    Options                              result;
    bool                                 help = false;
    std::optional<std::filesystem::path> child_path;
    for(int arg_i = 1; arg_i < argc; ++arg_i)
    {
        const auto current_arg = std::wstring_view(argv[arg_i]);
        if(current_arg == L"--help")
        {
            help = true;
        }
        else if(current_arg == L"--suspend")
        {
            result.suspend = true;
        }
        else if(current_arg == L"--wait")
        {
            result.wait = true;
        }
        else if(current_arg == L"--no-app-name")
        {
            result.no_app_name = true;
        }
        else if(current_arg == L"--init-time")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --init-time.");
            const auto next_arg = utf16_to_utf8(argv[++arg_i]);

            std::chrono::milliseconds::rep mills;

            auto chars_result = std::from_chars(next_arg.data(), next_arg.data() + next_arg.size(), mills);
            if(chars_result.ec != std::errc{}) print_error_and_exit(L"Invalid argument for --init-time.");

            result.init_sleep_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(mills));
        }
        else if(current_arg == L"--suspend-time")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --suspend-time.");
            const auto next_arg = utf16_to_utf8(argv[++arg_i]);

            std::chrono::milliseconds::rep mills;

            auto chars_result = std::from_chars(next_arg.data(), next_arg.data() + next_arg.size(), mills);
            if(chars_result.ec != std::errc{}) print_error_and_exit(L"Invalid argument for --suspend-time.");

            result.suspend_sleep_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(mills));
        }
        else if(current_arg == L"--final-time")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --final-time.");
            const auto next_arg = utf16_to_utf8(argv[++arg_i]);

            std::chrono::milliseconds::rep mills;

            auto chars_result = std::from_chars(next_arg.data(), next_arg.data() + next_arg.size(), mills);
            if(chars_result.ec != std::errc{}) print_error_and_exit(L"Invalid argument for --final-time.");

            result.final_sleep_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(mills));
        }
        else if(current_arg.starts_with(L"--"))
        {
            print_error_and_exit(std::format(L"Unknown command line argument: {}", current_arg));
        }
        else if(current_arg == L"-")
        {
            const auto arg_next = arg_i + 1;
            result.child_args.reserve(argc - arg_next);
            for(int arg_j = arg_next; arg_j < argc; ++arg_j)
            {
                result.child_args.emplace_back(argv[arg_j]);
            }
            break;
        }
        else if(child_path.has_value())
        {
            print_error_and_exit(std::format(L"Multiple paths not supported: first was '{}' current is '{}'", child_path->c_str(), current_arg));
        }
        else
        {
            child_path = current_arg;
        }
    }

    if(help)
    {
        print_usage_and_exit(EXIT_SUCCESS);
    }

    if(!child_path)
    {
        print_error_and_exit(L"Missing child executable path.");
    }
    result.child_path = *child_path;

    return result;
}

void append_quoted_command_line_argument(std::wstring& command_line, std::wstring_view arg)
{
    // This is based on:
    //   https://learn.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way

    if(arg.empty()) return;

    if(!command_line.empty()) command_line.push_back(L' ');

    if(arg.find_first_of(L" \t\n\v\"") == std::wstring_view::npos)
    {
        // Simple case: does not need any special handling
        command_line.append(arg);
        return;
    }

    command_line.push_back(L'"');

    for(auto it = arg.begin();; ++it)
    {
        std::size_t num_backslashes = 0;

        while(it != arg.end() && *it == L'\\')
        {
            ++it;
            ++num_backslashes;
        }

        if(it == arg.end())
        {
            command_line.append(num_backslashes * 2, L'\\');
            break;
        }
        if(*it == L'"')
        {
            command_line.append(num_backslashes * 2 + 1, L'\\');
            command_line.push_back(*it);
        }
        else
        {
            command_line.append(num_backslashes, L'\\');
            command_line.push_back(*it);
        }
    }

    command_line.push_back(L'"');
}

std::optional<std::wstring> make_command_line(const Options& opts)
{
    if(opts.child_args.empty() && !opts.no_app_name) return std::nullopt;

    std::wstring command_line;

    append_quoted_command_line_argument(command_line, opts.child_path.native());

    for(const auto& arg : opts.child_args)
    {
        append_quoted_command_line_argument(command_line, arg);
    }

    return command_line;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
int wmain(int argc, wchar_t* argv[])
{
    const auto opts = parse_command_line(argc, argv);

    std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): initialized" << std::endl;

    std::this_thread::sleep_for(opts.init_sleep_time);

    auto command_line = make_command_line(opts);

    const DWORD         creation_flags = opts.suspend ? CREATE_SUSPENDED : 0;
    STARTUPINFOW        info           = {sizeof(info)};
    PROCESS_INFORMATION process_info;

    const auto result = CreateProcessW(
        opts.no_app_name ? nullptr : opts.child_path.c_str(),
        command_line ? command_line->data() : nullptr,
        nullptr,
        nullptr,
        FALSE,
        creation_flags,
        nullptr,
        nullptr,
        &info,
        &process_info);

    if(result == FALSE)
    {
        std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): failed to create child process: " << result << std::endl;
        return EXIT_FAILURE;
    }

    std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): started process " << opts.child_path.c_str() << L"; PID " << process_info.dwProcessId << L"; TID " << process_info.dwThreadId << std::endl;

    if(opts.suspend)
    {
        auto* const child_main_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, process_info.dwThreadId);
        if(child_main_thread == nullptr)
        {
            std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): failed to open child process thread: " << result << std::endl;
            return EXIT_FAILURE;
        }

        std::this_thread::sleep_for(opts.suspend_sleep_time);

        ResumeThread(child_main_thread);
        std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): resumed child" << std::endl;
        CloseHandle(child_main_thread);
    }

    std::this_thread::sleep_for(opts.final_sleep_time);

    if(opts.wait)
    {
        std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): wait for child" << std::endl;
        WaitForSingleObject(process_info.hProcess, INFINITE);
    }

    std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): terminating" << std::endl;

    return EXIT_SUCCESS;
}
