
#include <iostream>
#include <thread>
#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(int argc, char* argv[])
{
    std::wcout << L"  CALLEE (" << GetCurrentProcessId() << L"): initialized" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(15));

    std::wcout << L"  CALLEE (" << GetCurrentProcessId() << L"): terminating" << std::endl;

    return EXIT_SUCCESS;
}
