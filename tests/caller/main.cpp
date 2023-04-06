
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(int argc, char* argv[])
{
    std::filesystem::path callee_path;

    if(argc < 2)
    {
        callee_path = R"(C:\Users\aziegenhagel\build\childdebugger-concord\debug\tests\bin\callee.exe)";
    }
    else
    {
        callee_path = argv[1];
    }

    std::cout << "This is CALLER " << GetCurrentProcessId() << std::endl;

    // std::this_thread::sleep_for(std::chrono::seconds(5));

    const auto* path = callee_path.c_str();

    STARTUPINFOW info={sizeof(info)};
    PROCESS_INFORMATION processInfo;
    const auto result = CreateProcessW(path,
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &info,
        &processInfo);

    if(FAILED(result)) return EXIT_FAILURE;

    std::cout << "Started process " << callee_path.string() << "; PID " << processInfo.dwProcessId << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(10));

    std::cout << "End CALLER " << GetCurrentProcessId() << std::endl;

    return EXIT_SUCCESS;
}
