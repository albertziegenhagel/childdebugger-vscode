
#include <iostream>
#include <thread>
#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main(int argc, char* argv[])
{
    std::cout << "This is CALLEE " << GetCurrentProcessId() << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(10));

    std::cout << "End CALLEE " << GetCurrentProcessId() << std::endl;

    return EXIT_SUCCESS;
}
