#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
# include <Windows.h>
# include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <cstdio>

#include "ntsuspend.h"

typedef LONG (NTAPI *pNtSuspendProcess )( HANDLE ProcessHandle );
pNtSuspendProcess NtSuspendProcess;
typedef LONG (NTAPI *pNtResumeProcess )( HANDLE ProcessHandle );
pNtResumeProcess NtResumeProcess;

int ImportNtDll(void)
{
    HMODULE ntdll = ::GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return 0;

    NtSuspendProcess = (pNtSuspendProcess)::GetProcAddress(ntdll, "NtSuspendProcess");
    if (NtSuspendProcess)
        NtResumeProcess = (pNtResumeProcess)::GetProcAddress(ntdll, "NtResumeProcess");

    return !!(NtSuspendProcess && NtResumeProcess);
}

bool NT_Suspend(HANDLE hProcess)
{
    LONG status = NtSuspendProcess(hProcess);
    if (!NT_SUCCESS(status)) {
        return false;
    }
    return true;
}

bool NT_Resume(HANDLE hProcess)
{
    LONG status = NtResumeProcess(hProcess);
    if (!NT_SUCCESS(status)) {
        return false;
    }
    return true;
}
