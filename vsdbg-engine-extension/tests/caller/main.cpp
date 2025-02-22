
#include <atomic>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <syncstream>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WtsApi32.h>

enum class CreateProcessMethod
{
    classic,
    user,
    token,
    logon
};

struct Options
{
    std::filesystem::path     child_path;
    std::vector<std::wstring> child_args;

    bool         suspend     = false;
    bool         wait        = false;
    bool         no_app_name = false;
    bool         ansi        = false;
    unsigned int threads     = 0;

    CreateProcessMethod method = CreateProcessMethod::classic;

    std::optional<std::wstring> user_name;
    std::optional<std::wstring> user_domain;
    std::optional<std::wstring> user_password;

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

std::string utf16_to_ansi(const std::wstring& input)
{
    if(input.empty()) return {};

    const auto result_size = WideCharToMultiByte(CP_ACP, 0,
                                                 input.data(), static_cast<int>(input.size()),
                                                 nullptr, 0,
                                                 nullptr, nullptr);
    assert(result_size > 0);

    std::string result(result_size, '\0');
    const auto  bytes_converted = WideCharToMultiByte(CP_ACP, 0,
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
               << L"  --method <STR>   Which kind of create-process method to use:\n"
               << L"                   'classic' - CreateProcessW(A).\n"
               << L"                   'user'    - CreateProcessAsUserW(A).\n"
               << L"                   'token'   - CreateProcessWithTokenW.\n"
               << L"                   'logon'   - CreateProcessWithLogonW.\n"
               << L"                   default: 'classic'\n"
               << L"  --user-name <STR>\n"
               << L"                   User name to use for 'logon' process creation\n"
               << L"                   method.\n"
               << L"  --user-domain <STR>\n"
               << L"                   Domain of the user to use for 'logon' process\n"
               << L"                   creation method.\n"
               << L"  --user-password <STR>\n"
               << L"                   Password of the user to use for 'logon' process\n"
               << L"                   creation method.\n"
               << L"  --ansi           Use the ansi versions of the create-process\n"
               << L"                   functions if available.\n"
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
               << L"  --threads <N>    Start child processes from <N> parallel threads\n"
               << L"                   at the same time instead of only one child from\n"
               << L"                   the main thread.\n"
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
        else if(current_arg == L"--method")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --method.");
            const auto next_arg = std::wstring_view(argv[++arg_i]);

            if(next_arg == L"classic")
            {
                result.method = CreateProcessMethod::classic;
            }
            else if(next_arg == L"user")
            {
                result.method = CreateProcessMethod::user;
            }
            else if(next_arg == L"token")
            {
                result.method = CreateProcessMethod::token;
            }
            else if(next_arg == L"logon")
            {
                result.method = CreateProcessMethod::logon;
            }
            else
            {
                print_error_and_exit(L"Invalid argument for --method.");
            }
        }
        else if(current_arg == L"--user-name")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --user-name.");
            result.user_name = std::wstring_view(argv[++arg_i]);
        }
        else if(current_arg == L"--user-domain")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --user-domain.");
            result.user_domain = std::wstring_view(argv[++arg_i]);
        }
        else if(current_arg == L"--user-password")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --user-password.");
            result.user_password = std::wstring_view(argv[++arg_i]);
        }
        else if(current_arg == L"--ansi")
        {
            result.ansi = true;
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
        else if(current_arg == L"--threads")
        {
            if(argc <= arg_i + 1) print_error_and_exit(L"Missing argument for --threads.");
            const auto next_arg = utf16_to_utf8(argv[++arg_i]);

            auto chars_result = std::from_chars(next_arg.data(), next_arg.data() + next_arg.size(), result.threads);
            if(chars_result.ec != std::errc{}) print_error_and_exit(L"Invalid argument for --threads.");
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

auto create_output_pipes()
{
    SECURITY_ATTRIBUTES security_attributes  = {sizeof(SECURITY_ATTRIBUTES)};
    security_attributes.bInheritHandle       = TRUE;
    security_attributes.lpSecurityDescriptor = nullptr;

    HANDLE out_read;
    HANDLE out_write;
    HANDLE err_read;
    HANDLE err_write;

    if(CreatePipe(&out_read, &out_write, &security_attributes, 0) == FALSE)
    {
        std::wosyncstream(std::wcout) << L"Failed to create out pipe." << std::endl;
        std::quick_exit(EXIT_FAILURE);
    }
    if(CreatePipe(&err_read, &err_write, &security_attributes, 0) == FALSE)
    {
        std::wosyncstream(std::wcout) << L"Failed to create err pipe." << std::endl;
        std::quick_exit(EXIT_FAILURE);
    }

    return std::make_tuple(out_read, out_write, err_read, err_write);
}

void start_forward_output_thread(HANDLE out_read, HANDLE err_read)
{
    std::thread forward_output_thread(
        [out_read, err_read]()
        {
            auto* const stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            auto* const stderr_handle = GetStdHandle(STD_ERROR_HANDLE);

            std::array<std::byte, 128> buffer;

            DWORD read    = 0;
            DWORD written = 0;
            while(true)
            {
                while(ReadFile(out_read, buffer.data(), buffer.size(), &read, nullptr) == TRUE)
                {
                    WriteFile(stdout_handle, buffer.data(), read, &written, nullptr);
                }
                while(ReadFile(err_read, buffer.data(), buffer.size(), &read, nullptr) == TRUE)
                {
                    WriteFile(stderr_handle, buffer.data(), read, &written, nullptr);
                }
            }
        });

    forward_output_thread.detach();
}

DWORD run_create_process(const Options&       opts,
                         PROCESS_INFORMATION& process_info)
{
    auto command_line = make_command_line(opts);

    const DWORD creation_flags = opts.suspend ? CREATE_SUSPENDED : 0;

    switch(opts.method)
    {
    case CreateProcessMethod::classic:
    {
        if(opts.ansi)
        {
            STARTUPINFOA info = {sizeof(info)};

            const auto child_path_a   = utf16_to_ansi(opts.child_path.native());
            auto       command_line_a = command_line ? std::make_optional(utf16_to_ansi(command_line.value())) : std::nullopt;

            return CreateProcessA(
                opts.no_app_name ? nullptr : child_path_a.c_str(),
                command_line_a ? command_line_a->data() : nullptr,
                nullptr,
                nullptr,
                FALSE,
                creation_flags,
                nullptr,
                nullptr,
                &info,
                &process_info);
        }

        STARTUPINFOW info = {sizeof(info)};

        return CreateProcessW(
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
    }
    break;
    case CreateProcessMethod::user:
    {
        HANDLE user_token;
        if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &user_token) != TRUE)
        {
            std::wosyncstream(std::wcout) << L"Failed to get user token of current process." << std::endl;
            std::quick_exit(EXIT_FAILURE);
        }

        if(opts.ansi)
        {
            STARTUPINFOA info = {sizeof(info)};

            const auto child_path_a   = utf16_to_ansi(opts.child_path.native());
            auto       command_line_a = command_line ? std::make_optional(utf16_to_ansi(command_line.value())) : std::nullopt;

            const auto result = CreateProcessAsUserA(
                user_token,
                opts.no_app_name ? nullptr : child_path_a.c_str(),
                command_line_a ? command_line_a->data() : nullptr,
                nullptr,
                nullptr,
                FALSE,
                creation_flags,
                nullptr,
                nullptr,
                &info,
                &process_info);

            CloseHandle(user_token);

            return result;
        }

        STARTUPINFOW info = {sizeof(info)};

        const auto result = CreateProcessAsUserW(
            user_token,
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

        CloseHandle(user_token);

        return result;
    }
    break;
    case CreateProcessMethod::token:
    {
        HANDLE token = nullptr;
        if(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &token) != TRUE)
        {
            std::wosyncstream(std::wcout) << L"Failed to get token of current process." << std::endl;
            std::quick_exit(EXIT_FAILURE);
        }

        HANDLE token_duplicate = nullptr;
        if(DuplicateTokenEx(token, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, nullptr, SecurityImpersonation, TokenPrimary, &token_duplicate) != TRUE)
        {
            CloseHandle(token);
            std::wosyncstream(std::wcout) << L"Failed to duplicate process token." << std::endl;
            std::quick_exit(EXIT_FAILURE);
        }

        const auto [out_read, out_write, err_read, err_write] = create_output_pipes();

        STARTUPINFOW info = {sizeof(info)};
        info.hStdOutput   = out_write;
        info.hStdError    = err_write;
        info.dwFlags      = STARTF_USESTDHANDLES;

        const auto result = CreateProcessWithTokenW(
            token_duplicate,
            0,
            opts.no_app_name ? nullptr : opts.child_path.c_str(),
            command_line ? command_line->data() : nullptr,
            creation_flags | CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &info,
            &process_info);

        if(result == TRUE)
        {
            start_forward_output_thread(out_read, err_read);
        }

        CloseHandle(token_duplicate);
        CloseHandle(token);

        return result;
    }
    break;
    case CreateProcessMethod::logon:
    {
        const auto [out_read, out_write, err_read, err_write] = create_output_pipes();

        STARTUPINFOW info = {sizeof(info)};
        info.hStdOutput   = out_write;
        info.hStdError    = err_write;
        info.dwFlags      = STARTF_USESTDHANDLES;

        const auto result = CreateProcessWithLogonW(
            opts.user_name ? opts.user_name->c_str() : nullptr,
            opts.user_domain ? opts.user_domain->c_str() : nullptr,
            opts.user_password ? opts.user_password->c_str() : nullptr,
            0,
            opts.no_app_name ? nullptr : opts.child_path.c_str(),
            command_line ? command_line->data() : nullptr,
            creation_flags | CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &info,
            &process_info);

        if(result == TRUE)
        {
            start_forward_output_thread(out_read, err_read);
        }

        return result;
    }
    break;
    default:
        std::wcout << L"Internal error: invalid create-process method." << std::endl;
        std::quick_exit(EXIT_FAILURE);
    }
}

int start_child(const Options& opts)
{
    PROCESS_INFORMATION process_info = {};

    const auto pid = GetCurrentProcessId();
    const auto tid = GetCurrentThreadId();

    const auto result = run_create_process(opts, process_info);
    if(result == FALSE)
    {
        const auto error_code = GetLastError();
        std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L", " << tid << L"): failed to create child process: " << error_code << std::endl;
        return EXIT_FAILURE;
    }

    std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L", " << tid << L"): started process " << opts.child_path.c_str() << L"; PID " << process_info.dwProcessId << L"; TID " << process_info.dwThreadId << std::endl;

    if(opts.suspend)
    {
        auto* const child_main_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, process_info.dwThreadId);
        if(child_main_thread == nullptr)
        {
            std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L", " << tid << L"): failed to open child process thread: " << result << std::endl;
            CloseHandle(process_info.hThread);
            CloseHandle(process_info.hProcess);
            return EXIT_FAILURE;
        }

        std::this_thread::sleep_for(opts.suspend_sleep_time);

        ResumeThread(child_main_thread);
        std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L", " << tid << L"): resumed child" << std::endl;
        CloseHandle(child_main_thread);
    }

    std::this_thread::sleep_for(opts.final_sleep_time);

    if(opts.wait)
    {
        std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L", " << tid << L"): wait for child" << std::endl;
        WaitForSingleObject(process_info.hProcess, INFINITE);
    }

    std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L", " << tid << L"): terminating thread" << std::endl;

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

    return EXIT_SUCCESS;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
int wmain(int argc, wchar_t* argv[])
{
    const auto opts = parse_command_line(argc, argv);

    const auto pid = GetCurrentProcessId();

    std::wosyncstream(std::wcout) << L"  CALLER (" << pid << L"): initialized" << std::endl;

    std::this_thread::sleep_for(opts.init_sleep_time);

    if(opts.threads > 0)
    {
        std::vector<std::thread> threads;
        std::atomic<int>         exit_code = EXIT_SUCCESS;
        for(unsigned int i = 0; i < opts.threads; ++i)
        {
            threads.emplace_back(
                [opts, &exit_code]
                {
                    if(start_child(opts) != EXIT_SUCCESS)
                    {
                        exit_code = EXIT_FAILURE;
                    }
                });
        }
        for(auto& thread : threads)
        {
            thread.join();
        }
        return exit_code;
    }

    return start_child(opts);
}
