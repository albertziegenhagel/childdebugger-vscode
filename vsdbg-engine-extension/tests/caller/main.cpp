
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct options
{
    std::filesystem::path child_path;
    std::vector<std::wstring> child_args;

    bool suspend = false;
    bool wait = false;
    bool no_app_name = false;

    std::chrono::seconds init_sleep_time    = std::chrono::seconds(1);
    std::chrono::seconds suspend_sleep_time = std::chrono::seconds(30);
    std::chrono::seconds final_sleep_time   = std::chrono::seconds(10);
};

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
               << L"                   lpcommand_line instead.\n"
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

options parse_command_line(int argc, wchar_t* argv[]) // NOLINT(modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
{
    options result;
    bool    help = false;
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
                result.child_args.push_back(argv[arg_j]);
            }
            break;
        }
        else if(child_path != std::nullopt)
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
        else if(*it == L'"')
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

std::optional<std::wstring> make_command_line(const options& opts)
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

int wmain(int argc, wchar_t* argv[])
{
    const auto opts = parse_command_line(argc, argv);

    std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): initialized" << std::endl;

    std::this_thread::sleep_for(opts.init_sleep_time);

    auto command_line = make_command_line(opts);

    const DWORD creation_flags = opts.suspend ? CREATE_SUSPENDED : 0;
    STARTUPINFOW info={sizeof(info)};
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
        const auto childMainThread = OpenThread(THREAD_SUSPEND_RESUME, false, process_info.dwThreadId);
        if(childMainThread == nullptr)
        {
            std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): failed to open child process thread: " << result << std::endl;
            return EXIT_FAILURE;
        }

        std::this_thread::sleep_for(opts.suspend_sleep_time);

        ResumeThread(childMainThread);
        std::wcout << L"  CALLER (" << GetCurrentProcessId() << L"): resumed child" << std::endl;
        CloseHandle(childMainThread);
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
