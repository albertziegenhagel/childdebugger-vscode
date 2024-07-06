#include <string>
#include <cassert>
#include <thread>
#include <chrono>
#include <filesystem>
#include <memory>

#include <iostream> // TODO: remove

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include <tlhelp32.h>
#include <psapi.h>

#include <vsdebugeng.h>
#include <vsdebugeng.templates.h>

#include "ChildDebuggerService.h"

using namespace Microsoft::VisualStudio::Debugger;

// Source ID for breakpoints that we create for child process debugging.
// This allows this extension to only get notified on breakpoints that it created itself.
// {0BB89D05-9EAD-4295-9A74-A241583DE420} (same as in vsdconfigxml filter)
static const GUID sourceId = { 0x0bb89d05, 0x9ead, 0x4295, { 0x9a, 0x74, 0xa2, 0x41, 0x58, 0x3d, 0xe4, 0x20 } };

// Takes the Wide-Char (UTF-16) encoded input string and returns it as an UTF-8 encoded string.
std::string utf8_encode(const std::wstring& input)
{
    if(input.empty()) return {};

    const auto result_size = WideCharToMultiByte(CP_UTF8, 0,
                                                 input.data(), static_cast<int>(input.size()),
                                                 nullptr, 0,
                                                 nullptr, nullptr);
    assert(result_size > 0);

    std::string result(result_size, '\0');
    const auto bytes_converted = WideCharToMultiByte(CP_UTF8, 0,
                                                     input.data(), static_cast<int>(input.size()),
                                                     result.data(), result_size,
                                                     nullptr, nullptr);
    assert(bytes_converted != 0);

    return result;
}

// Retrieve the path to the module (DLL) that holds this function.
std::optional<std::filesystem::path> get_current_module_path()
{
    HMODULE current_module = NULL;
    if(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&get_current_module_path, &current_module) == FALSE) return std::nullopt;

    WCHAR buffer[MAX_PATH]; // FIXME: handle paths longer than MAX_PATH
    const auto result_size = GetModuleFileNameW(current_module, buffer, MAX_PATH);
    if(result_size == 0) return std::nullopt;

    const auto result = std::filesystem::path(buffer).parent_path();
    if(result.empty()) return std::nullopt;

    return result;
}

// Returns true if the input string contains any of the strings in the `entries` argument.
bool contains_any(std::string_view input, const std::vector<std::string>& entries)
{
    for(const auto& entry : entries)
    {
        if(input.contains(entry)) return true;
    }
    return false;
}

#ifdef CreateProcess
#   undef CreateProcess
#endif

#ifdef CreateProcessAsUser
#   undef CreateProcessAsUser
#endif

enum class CreateFunctionType
{
    CreateProcess,
    CreateProcessAsUser,
    CreateProcessWithToken,
    CreateProcessWithLogon
};

// Base class for breakpoint information classes.
template<typename Interface>
class BaseObject : public Interface
{
    volatile LONG m_refCount;
    
public:
    virtual ULONG __stdcall AddRef() override
    {
        return (ULONG)InterlockedIncrement(&m_refCount);
    }
    virtual ULONG __stdcall Release() override
    {
        ULONG result = (ULONG)InterlockedDecrement(&m_refCount);
        if (result == 0)
        {
            delete this;
        }
        return result;
    }
    virtual HRESULT __stdcall QueryInterface(REFIID riid, _Deref_out_ void** ppv) override
    {
        if (riid == __uuidof(IUnknown))
        {
            *ppv = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }
        // This example is implementing the optional interface IDkmDisposableDataItem
        else if (riid == __uuidof(IDkmDisposableDataItem))
        {
            *ppv = static_cast<IDkmDisposableDataItem*>(this);
            AddRef();
            return S_OK;
        }
        else
        {
            *ppv = NULL;
            return E_NOINTERFACE;
        }
    }
};

// Class holding additional information for breakpoints to be triggered on
// a call to any of the process creation functions.
class __declspec(uuid("{1483C347-BDAD-4626-B33F-D16970542239}")) CreateInInfo :
    public BaseObject<IDkmDisposableDataItem>
{
    BOOL isUnicode_;
    CreateFunctionType functionType_;
public:
    virtual HRESULT __stdcall OnClose() override
    {
        return S_OK;
    }
    
    explicit CreateInInfo(BOOL isUnicode, CreateFunctionType functionType) :
        isUnicode_(isUnicode),
        functionType_(functionType)
    {}

    UINT64 GetIsUnicode() const
    {
        return isUnicode_;
    }
    
    CreateFunctionType GetFunctionType() const
    {
        return functionType_;
    }
};

// Class holding additional information for breakpoints to be triggered when
// we return from a  call to any of the process creation functions.
class __declspec(uuid("{F1AB4299-C3EB-47C5-83B7-813E28B9DA89}")) CreateOutInfo :
    public BaseObject<IDkmDisposableDataItem>
{
    UINT64 lpProcessInformation_;
    bool suspended_;
public:
    virtual HRESULT __stdcall OnClose() override
    {
        return S_OK;
    }

    explicit CreateOutInfo(UINT64 lpProcessInformation, bool suspended) :
        lpProcessInformation_(lpProcessInformation),
        suspended_(suspended)
    {}

    UINT64 GetProcessInformationAddress() const
    {
        return lpProcessInformation_;
    }
    
    bool GetSuspended() const
    {
        return suspended_;
    }
};

struct CreateProcessStack
{
    UINT64 returnAddress;

    UINT64 lpApplicationName;
    UINT64 lpCommandLine;
    UINT64 lpProcessAttributes;
    UINT64 lpThreadAttributes;
    UINT8  bInheritHandles;
    UINT8  Padding1;
    UINT16 Padding2;
    UINT32 Padding3;
    UINT32 dwCreationFlags;
    UINT32 Padding4;
    UINT64 lpEnvironment;
    UINT64 lpCurrentDirectory;
    UINT64 lpStartupInfo;
    UINT64 lpProcessInformation;
};

// TODO: add parameter stack definitions for `CreateProcessAsUser`, `CreateProcessWithToken` and `CreateProcessWithLogon`.


std::optional<std::vector<std::string>> read_no_suspend(const std::filesystem::path& no_suspend_file_path)
{
    std::ifstream no_suspend_file(no_suspend_file_path);

    if(!no_suspend_file.is_open()) return std::nullopt;

    std::vector<std::string> result;
    std::string line;
    while(std::getline(no_suspend_file, line))
    {
        if(line.empty()) continue;
        if(line.starts_with('#')) continue;
        result.push_back(line);
    }
    return result;
}

CChildDebuggerService::CChildDebuggerService()
{
    const auto* const log_file_name    = "ChildDebugger.log";
    const auto* const no_suspend_file_name = "ChildDebugger-no_suspend.txt";

    const auto root = get_current_module_path();

    const auto log_file_path = root ? (*root / log_file_name) : log_file_name;
    logFile.open(log_file_path, std::ios::out | std::ios::app);

    const auto no_suspend_file_path = root ? (*root / no_suspend_file_name) : no_suspend_file_name;
    if(std::filesystem::is_regular_file(no_suspend_file_path))
    {
        auto no_suspend_data = read_no_suspend(no_suspend_file_path);
        if(no_suspend_data == std::nullopt)
        {
            logFile << "Failed to load no-suspend executable names from " << no_suspend_file_path.string() << std::endl;
        }
        else
        {
            no_suspend_exe_names = std::move(*no_suspend_data);
            logFile << "Loaded no-suspend executable names from " << no_suspend_file_path.string() << ":\n";
            for(const auto& name : no_suspend_exe_names)
            {
                logFile << "  " << name << "\n";
            }
            logFile.flush();
        }
    }
    else
    {
        logFile << "Skip loading no-suspend executable names from non-existent file " << no_suspend_file_path.string() << std::endl;
    }

    DkmString::Create(L"CreateProcessW", &createProcessFunctionNames[0]);
    DkmString::Create(L"CreateProcessA", &createProcessFunctionNames[1]);
    // FIXME: implement support for remaining process creation functions and active them here.
    // DkmString::Create(L"CreateProcessAsUserW", &createProcessFunctionNames[2]);
    // DkmString::Create(L"CreateProcessAsUserA", &createProcessFunctionNames[3]);
    // DkmString::Create(L"CreateProcessWithTokenW", &createProcessFunctionNames[4]);
    // DkmString::Create(L"CreateProcessWithLogonW", &createProcessFunctionNames[5]);
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnModuleInstanceLoad(
    DkmModuleInstance* pModuleInstance,
    DkmWorkList* pWorkList,
    DkmEventDescriptorS* pEventDescriptor)
{
    // Check whether the loaded module is one of the Windows core DLLs that provide any of the Win32 API
    // functions for child process creation that we are interested in.

    // If it is not a native module, we are not interested (since the Windows core DLLs are native).
    auto* const nativeModuleInstance = Native::DkmNativeModuleInstance::TryCast(pModuleInstance);
    if(nativeModuleInstance == nullptr) return S_OK;

    // kernel32.dll provides:
    //  - CreateProcessA / CreateProcessW
    // advapi32.dll provides:
    //  - CreateProcessAsUserA / CreateProcessAsUserW
    //  - CreateProcessWithTokenW
    //  - CreateProcessWithLogonW
    if(DkmString::CompareOrdinalIgnoreCase(pModuleInstance->Name(), L"kernel32.dll") != 0 &&
       DkmString::CompareOrdinalIgnoreCase(pModuleInstance->Name(), L"advapi32.dll") != 0)
    {
        return S_OK;
    }

    // Now, try to find any of the supported process creation functions in this module and create
    // a breakpoint for any that we find.
    for(auto& functionName : createProcessFunctionNames)
    {
        if(DkmString::IsNullOrEmpty(functionName)) continue;

        // Try to find the address of the current function in the module.
        CComPtr<Native::DkmNativeInstructionAddress> address;
        if(nativeModuleInstance->FindExportName(functionName, true, &address) != S_OK) continue;

        logFile << "OnModuleInstanceLoad (Debugger PID " << GetCurrentProcessId() << ")\n";
        logFile << "  " << utf8_encode(pModuleInstance->Name()->Value()) << "\n";
        logFile << "  Base address " << pModuleInstance->BaseAddress() << "\n";
        logFile << "  Function address " << utf8_encode(functionName->Value()) << " @" << address->RVA() << "\n";
        logFile.flush();

        // FIXME: use correct function type for the current `functionName`.
        const auto functionType = CreateFunctionType::CreateProcess;

        // Attach some information to the breakpoint about the function it has been generated for.
        CComPtr<CreateInInfo> inInfo;
        inInfo.Attach(new CreateInInfo(functionName->Value()[functionName->Length() - 1] == L'W', functionType));

        CComPtr<Breakpoints::DkmRuntimeInstructionBreakpoint> breakpoint;
        if(Breakpoints::DkmRuntimeInstructionBreakpoint::Create(sourceId, nullptr, address, false, inInfo, &breakpoint) != S_OK)
        {
            logFile << "  FAILED to create breakpoint!\n";
            logFile.flush();
            continue;
        }

        if(breakpoint->Enable() != S_OK)
        {
            logFile << "  FAILED to enable breakpoint!\n";
            logFile.flush();
            continue;
        }
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnRuntimeBreakpoint(
    Breakpoints::DkmRuntimeBreakpoint* pRuntimeBreakpoint,
    DkmThread* pThread,
    bool HasException,
    DkmEventDescriptorS* pEventDescriptor)
{
    logFile << "OnRuntimeBreakpoint (Debugger PID " << GetCurrentProcessId() << ")\n";
    logFile.flush();

    CComPtr<CreateInInfo> inInfo;
    pRuntimeBreakpoint->GetDataItem(&inInfo);
    if(inInfo)
    {
        // This is a breakpoint when entering a process creation function.
        // We will do the following things:
        //  - extract some information about the process being created from the arguments passed to the creation function.
        //  - determine whether we want to suspend the child process.
        //  - maybe, modify the passed arguments to force  suspended start.
        //  - create a new breakpoint that is triggered when the create process function is finished.

        logFile << "  In PID " << pThread->Process()->LivePart()->Id << ": Start CreateProcess: W " << inInfo->GetIsUnicode() << " Func " << (int)inInfo->GetFunctionType() << "\n";
        logFile.flush();

        // Retrieve the current register values, required to extract function call arguments.
        CONTEXT context;
        if(pThread->GetContext(CONTEXT_CONTROL | CONTEXT_INTEGER, &context, sizeof(CONTEXT)) != S_OK)
        {
            logFile << "  FAILED to retrieve thread context.\n";
            logFile.flush();
            return S_FALSE;
        }

        // By default, we will suspend the newly created process.
        // FIXME: correctly take both, the `lpApplicationName` as well as the `lpCommandLine` arguments
        //        into account when trying to determine whether a process should be suspended.
        bool shouldSuspend = true;

        // FIXME: support other creation functions than `CreateProcessA` and `CreateProcessW`.
        assert(inInfo->GetFunctionType() == CreateFunctionType::CreateProcess);

        // Extract the application name from the passed arguments.
        // Assuming x64 calling conventions, the pointer to the string in memory is stored in the
        // RCX register for `CreateProcessA` and `CreateProcessW`.
        if(context.Rcx != 0)
        {
            CAutoDkmArray<BYTE> applicationNameArray;
            if(pThread->Process()->ReadMemoryString(context.Rcx, DkmReadMemoryFlags::None, inInfo->GetIsUnicode() ? 2 : 1, 0x8000, &applicationNameArray) != S_OK)
            {
                logFile << "  FAILED to read application name argument.\n";
                logFile.flush();
                return S_FALSE;
            }

            if(inInfo->GetIsUnicode())
            {
                const auto applicationName = reinterpret_cast<wchar_t*>(applicationNameArray.Members);
                logFile << "  APP " << (applicationName ? utf8_encode(applicationName) : "") << "\n";
            }
            else
            {
                const auto applicationName = reinterpret_cast<char*>(applicationNameArray.Members);
                logFile << "  APP " << (applicationName ? applicationName : "") << "\n";
            }
            logFile.flush();
        }

        // Extract the command line from the passed arguments.
        // Assuming x64 calling conventions, the pointer to the string in memory is stored in the
        // RDX register for `CreateProcessA` and `CreateProcessW`.
        if(context.Rdx != 0)
        {
            CAutoDkmArray<BYTE> commandLineArray;
            if(pThread->Process()->ReadMemoryString(context.Rdx, DkmReadMemoryFlags::None, inInfo->GetIsUnicode() ? 2 : 1, 0x8000, &commandLineArray) != S_OK)
            {
                logFile << "  FAILED to read command line argument.\n";
                logFile.flush();
                return S_FALSE;
            }
            if(inInfo->GetIsUnicode())
            {
                const auto commandLine = reinterpret_cast<wchar_t*>(commandLineArray.Members);
                logFile << "  CL " << (commandLine ? utf8_encode(commandLine) : "") << "\n";
                if(commandLine && contains_any(utf8_encode(commandLine), no_suspend_exe_names)) shouldSuspend = false;
            }
            else
            {
                const auto commandLine = reinterpret_cast<char*>(commandLineArray.Members);
                logFile << "  CL " << (commandLine ? commandLine : "") << "\n";
                if(commandLine && contains_any(commandLine, no_suspend_exe_names)) shouldSuspend = false;
            }
            logFile.flush();
        }

        // The other function arguments are passed on the stack, hence we need to extract it.
        // Assuming x64 calling conventions, the pointer to the stack frame is stored in the
        // RSP register.
        CreateProcessStack stack;
        if(pThread->Process()->ReadMemory(context.Rsp, DkmReadMemoryFlags::None, &stack, sizeof(CreateProcessStack), nullptr) != S_OK)
        {
            logFile << "  FAILED to read stack.\n";
            logFile.flush();
            return S_FALSE;
        }

        // If want to suspend the child process and it is not already requested to be suspended
        // originally, we enforce a suspended process creation.
        bool forcedSuspension = false;
        if(shouldSuspend && (stack.dwCreationFlags & CREATE_SUSPENDED) == 0)
        {
            forcedSuspension = true;
            const auto newFlags = stack.dwCreationFlags | CREATE_SUSPENDED;

            CAutoDkmArray<BYTE> newFlagsBytes;
            DkmAllocArray(sizeof(stack.dwCreationFlags), &newFlagsBytes);
            memcpy(newFlagsBytes.Members, &newFlags, sizeof(stack.dwCreationFlags));
            if(pThread->Process()->WriteMemory(context.Rsp + offsetof(CreateProcessStack, dwCreationFlags), newFlagsBytes) != S_OK)
            {
                logFile << "  FAILED to force suspended start.\n";
                logFile.flush();
                return S_FALSE;
            }

            logFile << "  Force suspended start\n";
            logFile.flush();
        }
        else
        {
            logFile << "  Originally requested suspended start\n";
            logFile.flush();
        }

        // Now, retrieve the return address for this function call.
        UINT64 returnAddress;
        UINT64 frameBase;
        UINT64 vframe;
        if(pThread->GetCurrentFrameInfo(&returnAddress, &frameBase, &vframe) != S_OK)
        {
            logFile << "  FAILED to retrieve function return address.\n";
            logFile.flush();
            return S_FALSE;
        }

        CComPtr<DkmInstructionAddress> address;
        if(pThread->Process()->CreateNativeInstructionAddress(returnAddress, &address) != S_OK)
        {
            logFile << "  FAILED to create native instruction address from function return address.\n";
            logFile.flush();
            return S_FALSE;
        }

        // Create a new breakpoint to be triggered when the child process creation is done.
        CComPtr<CreateOutInfo> outInfo;
        outInfo.Attach(new CreateOutInfo(stack.lpProcessInformation, forcedSuspension));

        CComPtr<Breakpoints::DkmRuntimeInstructionBreakpoint> breakpoint;
        if(Breakpoints::DkmRuntimeInstructionBreakpoint::Create(sourceId, nullptr, address, false, outInfo, &breakpoint) != S_OK)
        {
            logFile << "  FAILED to create breakpoint!\n";
            logFile.flush();
            return S_FALSE;
        }

        if(breakpoint->Enable() != S_OK)
        {
            logFile << "  FAILED to enable breakpoint!\n";
            logFile.flush();
            return S_FALSE;
        }

        // TODO: to make sure all this does not impose any unwanted effects, we should
        //       suspend the current parent process here, and only resume it when the debugger
        //       has been attached successfully to the child process.

        return S_OK;
    }

    CComPtr<CreateOutInfo> outInfo;
    pRuntimeBreakpoint->GetDataItem(&outInfo);
    if(outInfo)
    {
        // This is a breakpoint when a process creation has been completed.
        // We will do the following things:
        //  - extract the process ID if of the created child process.
        //  - inform the debug client (VS Code) about the newly created process, so that it can attach to it.

        logFile << "  In PID " << pThread->Process()->LivePart()->Id << ": Finish CreateProcess" << "\n";
        logFile.flush();

        pRuntimeBreakpoint->Close(); // Remove this breakpoint. We will create a new one for the next call.

        // Retrieve the current register values, required to extract the function return value.
        CONTEXT context;
        if(pThread->GetContext(CONTEXT_CONTROL | CONTEXT_INTEGER, &context, sizeof(CONTEXT)) != S_OK)
        {
            logFile << "  FAILED to retrieve thread context.\n";
            logFile.flush();
            return S_FALSE;
        }

        // The RAX register holds the return value.
        logFile << "  CreateProcess returned " << context.Rax << "\n";
        if(context.Rax == 0)
        {
            // Nothing to attach to if the CreateProcess call failed.
            logFile.flush();
            return S_OK;
        }

        // Read the process information structure from the stack. This should have been populated with information
        // about the newly created process.
        PROCESS_INFORMATION procInfo;
        if(pThread->Process()->ReadMemory(outInfo->GetProcessInformationAddress(), DkmReadMemoryFlags::None, &procInfo, sizeof(PROCESS_INFORMATION), nullptr) != S_OK)
        {
            logFile << "  FAILED to read process information!\n";
            logFile.flush();
            return S_FALSE;
        }

        // Try to extract the application name of the created child process.
        std::wstring applicationName;
        const auto processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, procInfo.dwProcessId);
        if(processHandle)
        {
            WCHAR buffer[MAX_PATH];
            const auto size = GetProcessImageFileNameW(processHandle, buffer, MAX_PATH);
            if(size > 0)
            {
                applicationName = std::filesystem::path(buffer).filename().native();
            }
            CloseHandle(processHandle);
        }

        logFile << "  Child App Name " << utf8_encode(applicationName) << "\n";
        logFile << "  Child PID " << procInfo.dwProcessId << " TID " << procInfo.dwThreadId << "\n";
        logFile << "  Child P-HANDLE " << procInfo.hProcess << " T-HANDLE " << procInfo.hThread << "\n";
        logFile.flush();

        // Now comes the real HACK:
        // We need to inform the client (VS Code) about the new child process, so that it can attach to it.
        // Unfortunately `DkmDebugProcessRequest` does not seem to be implemented by the debug adapter used
        // in VS Code.
        // `DkmCustomMessage` does not seem to be implement either (and it is not clear yet where this would
        // be received).
        // So, we are going to abuse a `DkmUserMessage`. This messages will always be printed in the debug
        // console view of VS Code and can only transport text, but it is the only workaround I could find
        // so far.
        // The following messages is formatted in such a way, that we can hopefully parse all the information
        // back in the VS Code extension side.
        CComPtr<DkmString> messageStr;
        if(DkmString::Create((L"ChildDebugger: attach to child NAME '" + applicationName + L"' PID " + std::to_wstring(procInfo.dwProcessId) + L" TID " + std::to_wstring(procInfo.dwThreadId) + (outInfo->GetSuspended() ? L" SUSPENDED" : L" RUNNING") + L"\n").c_str(), &messageStr) != S_OK)
        {
            logFile << "  FAILED to create string for message!\n";
            logFile.flush();
            return S_FALSE;
        }

        CComPtr<DkmUserMessage> message;
        if(DkmUserMessage::Create(pThread->Connection(), pThread->Process(), DkmUserMessageOutputKind::UnfilteredOutputWindowMessage, messageStr, MB_OK, S_OK, &message) != S_OK)
        {
            logFile << "  FAILED to create user message!\n";
            logFile.flush();
            return S_FALSE;
        }

        if(message->Post() != S_OK)
        {
            logFile << "  FAILED to post user message!\n";
            logFile.flush();
            return S_FALSE;
        }

        return S_OK;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnProcessCreate(
        _In_ DkmProcess* pProcess,
        _In_ DkmWorkList* pWorkList,
        _In_ DkmEventDescriptor* pEventDescriptor)
{
    if(pProcess->LivePart() == nullptr) return S_OK;

    logFile << "OnProcessCreate (Debugger PID " << GetCurrentProcessId() << ")\n";
    logFile << "  " << utf8_encode(pProcess->Path()->Value()) << "\n";
    logFile << "  PID " << pProcess->LivePart()->Id << "\n";
    logFile.flush();

    if(contains_any(utf8_encode(pProcess->Path()->Value()), no_suspend_exe_names)) return S_OK;

    // FIXME: The following code resumes all threads of any process that we are starting to debug (except
    //        if it is ine the "no-suspend" list).
    //        The idea is that we are resuming child processes that we started suspended, but it has
    //        multiple issues:
    //          - We do not know whether this process has actually been started as a child process
    //            and has been suspended by us or by the original caller of CreateProcess.
    //          - The debugger seems to stay in a stopped state for the process, even after we resumed
    //            it here.

    // Take a snapshot of all running threads
    const auto hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(hThreadSnap == INVALID_HANDLE_VALUE)
    {
        logFile << "  CreateToolhelp32Snapshot failed " << hThreadSnap << "\n";
        logFile.flush();
        return S_FALSE;
    }

    // Start by extracting the first thread and iterate over it and all that follow.
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if(!Thread32First(hThreadSnap, &threadEntry))
    {
        CloseHandle(hThreadSnap);
        logFile << "  Thread32First failed\n";
        logFile.flush();
        return S_FALSE;
    }
    do
    {
        // Skip threads that do not belong to the process we just attached to.
        if(threadEntry.th32OwnerProcessID != pProcess->LivePart()->Id) continue;

        // Get a handle to the thread.
        logFile << "  THREAD ID " << threadEntry.th32ThreadID << " OWNER "<< threadEntry.th32OwnerProcessID << "\n";
        const auto hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threadEntry.th32ThreadID);
        if(hThread == nullptr)
        {
            logFile << "  Failed to open thread\n";
            logFile.flush();
            continue;
        }

        // Resume the thread.
        DWORD suspendCount = 0;
        // do
        {
            logFile << "  CALL ResumeThread\n";
            logFile.flush();
            suspendCount = ResumeThread(hThread);
            logFile << "  RESULT " << suspendCount << "\n";
            logFile.flush();
        }
        // while(suspendCount > 1 && suspendCount != -1);
        CloseHandle(hThread);

    } while(Thread32Next(hThreadSnap, &threadEntry));

    CloseHandle( hThreadSnap );

    return S_OK;
}
