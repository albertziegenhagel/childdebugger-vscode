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

#include "nlohmann/json.hpp"

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
// Takes the UTF-8 encoded input string and returns it as an Wide-Char (UTF-16) encoded string.
std::wstring utf16_encode(const std::string& input)
{
    if(input.empty()) return {};

    const auto result_size = MultiByteToWideChar(CP_UTF8, 0,
                                                 input.data(), static_cast<int>(input.size()),
                                                 nullptr, 0);
    assert(result_size > 0);

    std::wstring result(result_size, L'\0');
    const auto bytes_converted = MultiByteToWideChar(CP_UTF8, 0,
                                                     input.data(), static_cast<int>(input.size()),
                                                     result.data(), result_size);
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

enum class CustomMessageType
{
    Settings     = 1,
    ResumeChild  = 2,
    ResumeParent = 3,
    InformChild  = 4,
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


class __declspec(uuid("{0709D0FC-76B1-44E8-B781-E8C43461CFAC}")) ChildProcessItem :
    public BaseObject<IDkmDisposableDataItem>
{
    bool passedInitialBreakpoint_;
public:
    virtual HRESULT __stdcall OnClose() override
    {
        return S_OK;
    }

    explicit ChildProcessItem() :
        passedInitialBreakpoint_(false)
    {}
    
    bool GetPassedInitialBreakpoint() const
    {
        return passedInitialBreakpoint_;
    }

    void SetPassedInitialBreakpoint()
    {
        passedInitialBreakpoint_ = true;
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

    static DWORD64 getLpApplicationNameFromRegister(const CONTEXT& context)
    {
        return context.Rcx;
    }
    static DWORD64 getLpCommandLineFromRegister(const CONTEXT& context)
    {
        return context.Rdx;
    }
};

struct CreateProcessAsUserStack
{
    UINT64 returnAddress;

    UINT64 hToken;

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
    
    static DWORD64 getLpApplicationNameFromRegister(const CONTEXT& context)
    {
        return context.Rdx;
    }
    static DWORD64 getLpCommandLineFromRegister(const CONTEXT& context)
    {
        return context.R8;
    }
};

// TODO: add parameter stack definitions for `CreateProcessWithToken` and `CreateProcessWithLogon`.



HRESULT readMemoryFromStringAt(
    DkmProcess* process,
    DWORD64 address,
    bool isUnicode,
    CComPtr<DkmString>& result)
{
    if(address == 0) return S_OK;

    CAutoDkmArray<BYTE> bytes;
    if(process->ReadMemoryString(address, DkmReadMemoryFlags::None, isUnicode ? 2 : 1, 0x8000, &bytes) != S_OK)
    {
        return S_FALSE;
    }

    if(isUnicode)
    {
        return DkmString::Create(reinterpret_cast<const wchar_t*>(bytes.Members), &result);
    }
    else
    {
        return DkmString::Create(CP_ACP, reinterpret_cast<const char*>(bytes.Members),  bytes.Length, &result);
    }
}

bool checkAttachToProcess(
    const ChildDebuggerSettings& settings,
    std::ofstream& logFile,
    const CComPtr<DkmString>& applicationName,
    const CComPtr<DkmString>& commandLine)
{
    if(!applicationName && !commandLine) return settings.attachOthers;

    for(const auto& config : settings.processConfigs)
    {
        logFile << "  Check process config: " << "\n";
        logFile << "    applicationName: " << (config.applicationName ? utf8_encode(*config.applicationName) : "<EMPTY>") << "\n";
        logFile << "    commandLine: " << (config.commandLine ? utf8_encode(*config.commandLine) : "<EMPTY>") << "\n";

        // Skip invalid, empty config
        if(!config.applicationName && !config.commandLine) continue;

        // If this entry has a process name, but we failed to extract one: skip
        if(config.applicationName && !applicationName) continue;
        
        // If this entry has a command line, but we failed to extract one: skip
        if(config.commandLine && !commandLine) continue;

        // Check whether we the application name matches
        if(applicationName)
        {
            // The current application name is shorter than the config: it can not match, so skip
            if(applicationName->Length() < config.applicationName->size()) continue;

            const auto applicationNameFinalPart = std::wstring_view(applicationName->Value(), applicationName->Length()).substr(applicationName->Length() - config.applicationName->size(), config.applicationName->size());

            if(DkmString::CompareOrdinalIgnoreCase(applicationNameFinalPart.data(), config.applicationName->c_str()) != 0) continue;
        }

        // Check whether we can find the command line
        if(commandLine && 
           !std::wstring_view(commandLine->Value(), commandLine->Length()).contains(*config.commandLine)) continue;

        logFile << "    matched. attach: " << config.attach << "\n";
        logFile.flush();
        return config.attach;
    }

    logFile << "  No process config match. attach: " << settings.attachOthers << "\n";
    logFile.flush();
    return settings.attachOthers;
}

template<typename StackType>
HRESULT handleCallToCreateProcess(
    const ChildDebuggerSettings& settings,
    std::ofstream& logFile,
    DkmThread* pThread,
    const CONTEXT& context,
    bool isUnicode)
{
    // Extract the application name from the passed arguments.
    // Assuming x64 calling conventions, the pointer to the string in memory is stored in the
    // RCX register for `CreateProcessA` and `CreateProcessW`.
    CComPtr<DkmString> applicationName;
    if(readMemoryFromStringAt(pThread->Process(), StackType::getLpApplicationNameFromRegister(context), isUnicode, applicationName) != S_OK)
    {
        logFile << "  FAILED to read application name argument.\n";
        logFile.flush();
        return S_FALSE;
    }
    if(applicationName)
    {
        logFile << "  APP " << utf8_encode(applicationName->Value()) << "\n";
        logFile.flush();
    }

    // Extract the command line from the passed arguments.
    // Assuming x64 calling conventions, the pointer to the string in memory is stored in the
    // RDX register for `CreateProcessA` and `CreateProcessW`.
    CComPtr<DkmString> commandLine;
    if(readMemoryFromStringAt(pThread->Process(), StackType::getLpCommandLineFromRegister(context), isUnicode, commandLine) != S_OK)
    {
        logFile << "  FAILED to read command line argument.\n";
        logFile.flush();
        return S_FALSE;
    }
    if(commandLine)
    {
        logFile << "  CL " << utf8_encode(commandLine->Value()) << "\n";
        logFile.flush();
    }

    if(!checkAttachToProcess(settings, logFile, applicationName, commandLine)) return S_OK;

    // The other function arguments are passed on the stack, hence we need to extract it.
    // Assuming x64 calling conventions, the pointer to the stack frame is stored in the
    // RSP register.
    StackType stack;
    if(pThread->Process()->ReadMemory(context.Rsp, DkmReadMemoryFlags::None, &stack, sizeof(StackType), nullptr) != S_OK)
    {
        logFile << "  FAILED to read stack.\n";
        logFile.flush();
        return S_FALSE;
    }
    logFile << "  dwCreationFlags=" << stack.dwCreationFlags << "\n";

    // If want to suspend the child process and it is not already requested to be suspended
    // originally, we enforce a suspended process creation.
    bool forcedSuspension = false;
    if((stack.dwCreationFlags & CREATE_SUSPENDED) != 0)
    {
        logFile << "  Originally requested suspended start\n";
        logFile.flush();
    }
    else if(settings.suspendChildren)
    {
        forcedSuspension = true;
        const UINT32 newFlags = stack.dwCreationFlags | CREATE_SUSPENDED;

        CAutoDkmArray<BYTE> newFlagsBytes;
        DkmAllocArray(sizeof(stack.dwCreationFlags), &newFlagsBytes);
        memcpy(newFlagsBytes.Members, &newFlags, sizeof(stack.dwCreationFlags));
        if(pThread->Process()->WriteMemory(context.Rsp + offsetof(StackType, dwCreationFlags), newFlagsBytes) != S_OK)
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
        logFile << "  Skip suspended start\n";
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

    return S_OK;
}

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

    const auto root = get_current_module_path();

    const auto log_file_path = root ? (*root / log_file_name) : log_file_name;
    logFile.open(log_file_path, std::ios::out | std::ios::app);

    DkmString::Create(L"CreateProcessW", &createProcessFunctionNames[0]);
    DkmString::Create(L"CreateProcessA", &createProcessFunctionNames[1]);
    DkmString::Create(L"CreateProcessAsUserW", &createProcessFunctionNames[2]);
    DkmString::Create(L"CreateProcessAsUserA", &createProcessFunctionNames[3]);
    DkmString::Create(L"CreateProcessWithTokenW", &createProcessFunctionNames[4]);
    DkmString::Create(L"CreateProcessWithLogonW", &createProcessFunctionNames[5]);
}

template<typename T>
T try_get_or(const nlohmann::json& json, std::string_view name, T default_value)
{
    if(json.count(name) == 0) return default_value;
    return json.at(name).get<T>();
}

std::optional<std::wstring> try_get_optional_string(const nlohmann::json& json, std::string_view name)
{
    if(json.count(name) == 0) return std::nullopt;
    const auto str = json.at(name).get<std::string>();
    return utf16_encode(str);
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::SendLower(
        DkmCustomMessage* pCustomMessage,
        DkmCustomMessage** ppReplyMessage)
{
    logFile << "On CustomMessage (Debugger PID " << GetCurrentProcessId() << ")\n";
    logFile << "  MessageCode " << pCustomMessage->MessageCode() << "\n";
    logFile.flush();

    switch(CustomMessageType(pCustomMessage->MessageCode()))
    {
        case CustomMessageType::Settings:
        {
            if(pCustomMessage->Parameter1() == nullptr || pCustomMessage->Parameter1()->Type() != VT_BSTR) return S_FALSE;

            const auto settingsStr = pCustomMessage->Parameter1()->Value().bstrVal;

            // TODO: if we can find a reasonably small JSON parser library that can handle UTF-16 encoded
            // strings, we can probably get rid of this transcoding.
            const auto utf8SettingsStr = utf8_encode(settingsStr);

            try
            {
                const auto settingsJson = nlohmann::json::parse(utf8SettingsStr);
                
                settings.enabled = try_get_or(settingsJson, "enabled", false);
                settings.suspendParents = try_get_or(settingsJson, "suspendParents", true);
                settings.suspendChildren = try_get_or(settingsJson, "suspendChildren", true);
                settings.skipInitialBreakpoint = try_get_or(settingsJson, "skipInitialBreakpoint", true);
                settings.attachOthers = try_get_or(settingsJson, "attachOthers", true);

                settings.processConfigs.clear();
                if(settingsJson.count("processConfigs") > 0)
                {
                    for(const auto& configEntry : settingsJson.at("processConfigs"))
                    {
                        settings.processConfigs.push_back(
                            ProcessConfig{
                                .applicationName = try_get_optional_string(configEntry, "applicationName"),
                                .commandLine = try_get_optional_string(configEntry, "commandLine"),
                                .attach = try_get_or(configEntry, "attach", true)
                            }
                        );
                    }
                }
            }
            catch(const nlohmann::json::parse_error& ex)
            {
                logFile << "  Failed to parse JSON settings: " << ex.what() << "\n";
                logFile.flush();
            }
            logFile << "  enabled:               " << settings.enabled << "\n";
            logFile << "  suspendParents:        " << settings.suspendParents << "\n";
            logFile << "  suspendChildren:       " << settings.suspendChildren << "\n";
            logFile << "  skipInitialBreakpoint: " << settings.skipInitialBreakpoint << "\n";
            logFile << "  attachOthers:          " << settings.attachOthers << "\n";
            logFile << "  processConfigs:\n";
            for(const auto& config : settings.processConfigs)
            {
                logFile << "    applicationName:        " << (config.applicationName ? utf8_encode(*config.applicationName) : "<EMPTY>") << "\n";
                logFile << "    commandLine:            " << (config.commandLine ? utf8_encode(*config.commandLine) : "<EMPTY>") << "\n";
                logFile << "    attach:                 " << config.attach << "\n";
            }
            logFile.flush();
        }
        break;
        case CustomMessageType::ResumeChild:
        case CustomMessageType::InformChild:
        {
            if(!settings.enabled) return S_OK;

            if(pCustomMessage->Parameter1() == nullptr || pCustomMessage->Parameter1()->Type() != VT_I4) return S_FALSE;
            if(pCustomMessage->Parameter2() == nullptr || pCustomMessage->Parameter2()->Type() != VT_I4) return S_FALSE;

            const auto processId = pCustomMessage->Parameter1()->Value().lVal;
            const auto threadId = pCustomMessage->Parameter2()->Value().lVal;
            logFile << "  child PID " << processId << "\n";
            logFile << "  child TID " << threadId << "\n";

            CComPtr<DkmProcess> process;
            if(pCustomMessage->Connection()->FindLiveProcess(processId, &process) != S_OK)
            {
                logFile << "  Failed to find process\n";
                logFile.flush();
                return S_FALSE;
            }

            CComPtr<ChildProcessItem> childInfo;
            childInfo.Attach(new ChildProcessItem());

            process->SetDataItem(DkmDataCreationDisposition::CreateNew, childInfo);

            if(CustomMessageType(pCustomMessage->MessageCode()) == CustomMessageType::ResumeChild)
            {
                const auto hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threadId);
                if(hThread == nullptr)
                {
                    logFile << "  Failed to open thread\n";
                    logFile.flush();
                    return S_FALSE;
                }

                // Resume the thread.
                logFile << "  CALL ResumeThread\n";
                logFile.flush();
                const auto suspendCount = ResumeThread(hThread);
                logFile << "  RESULT " << suspendCount << "\n";
                logFile.flush();
                CloseHandle(hThread);
            }
        }
        break;
        case CustomMessageType::ResumeParent:
        {
            if(!settings.enabled) return S_OK;

            if(pCustomMessage->Parameter1() == nullptr || pCustomMessage->Parameter1()->Type() != VT_I4) return S_FALSE;
            if(pCustomMessage->Parameter2() == nullptr || pCustomMessage->Parameter2()->Type() != VT_I4) return S_FALSE;

            const auto processId = pCustomMessage->Parameter1()->Value().lVal;
            const auto threadId = pCustomMessage->Parameter2()->Value().lVal;
            logFile << "  parent PID " << processId << "\n";
            logFile << "  parent TID " << threadId << "\n";

            CComPtr<DkmProcess> process;
            if(pCustomMessage->Connection()->FindLiveProcess(processId, &process) != S_OK)
            {
                logFile << "  Failed to find process\n";
                logFile.flush();
                return S_FALSE;
            }

            CComPtr<DkmThread> thread;
            if(process->FindSystemThread(threadId, &thread) != S_OK)
            {
                logFile << "  Failed to find thread\n";
                logFile.flush();
                return S_FALSE;
            }

            UINT32 external_suspension_count;
            if(thread->Resume(true, &external_suspension_count) != S_OK)
            {
                logFile << "  Failed to resume thread\n";
                logFile.flush();
                return S_FALSE;
            }
        }
        break;
    }
    return S_OK;
}


HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnModuleInstanceLoad(
    DkmModuleInstance* pModuleInstance,
    DkmWorkList* pWorkList,
    DkmEventDescriptorS* pEventDescriptor)
{
    if(!settings.enabled) return S_OK;

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

        // TODO: Simplify this:
        const auto functionType = [&functionName]() -> CreateFunctionType {
            if(std::wstring_view(functionName->Value(), functionName->Length()).starts_with(L"CreateProcessWithLogon"))
            {
                return CreateFunctionType::CreateProcessWithLogon;
            }
            if(std::wstring_view(functionName->Value(), functionName->Length()).starts_with(L"CreateProcessWithToken"))
            {
                return CreateFunctionType::CreateProcessWithToken;
            }
            if(std::wstring_view(functionName->Value(), functionName->Length()).starts_with(L"CreateProcessAsUser"))
            {
                return CreateFunctionType::CreateProcessAsUser;
            }
            return CreateFunctionType::CreateProcess;
        }();

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
    if(!settings.enabled) return S_OK;

    logFile << "OnRuntimeBreakpoint (Debugger PID " << GetCurrentProcessId() << ")\n";
    wchar_t szGUID[64] = {0};
    StringFromGUID2(pRuntimeBreakpoint->SourceId(), szGUID, 64);
    logFile << "  Source ID:" << utf8_encode(szGUID) << "\n";
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

        // FIXME: support remaining creation functions `CreateProcessWithToken` and `CreateProcessWithLogon`.
        if(inInfo->GetFunctionType() == CreateFunctionType::CreateProcess)
        {
            return handleCallToCreateProcess<CreateProcessStack>(settings, logFile, pThread, context, inInfo->GetIsUnicode());
        }
        else if(inInfo->GetFunctionType() == CreateFunctionType::CreateProcessAsUser)
        {
            return handleCallToCreateProcess<CreateProcessAsUserStack>(settings, logFile, pThread, context, inInfo->GetIsUnicode());
        }
        else
        {
            logFile << "  Unsupported create function type: " << ((int)inInfo->GetFunctionType()) << ".\n";
            logFile.flush();
            return S_FALSE;
        }
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

        // To make sure all this does not impose any unwanted effects, we suspend
        // the current parent process here, and only resume it when the debugger
        // has been attached successfully to the child process.
        if(settings.suspendParents)
        {
            UINT32 external_suspension_count;
            if(pThread->Suspend(true, &external_suspension_count))
            {
                logFile << "  FAILED to suspend parent process.\n";
                logFile.flush();
                return S_FALSE;
            }
        }
        
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
        if(DkmString::Create((L"ChildDebugger: attach to child NAME '" + applicationName +
                                L"' PPID " + std::to_wstring(pThread->Process()->LivePart()->Id) +
                                L" PTID " + std::to_wstring(pThread->SystemPart()->Id) +
                                L" CPID " + std::to_wstring(procInfo.dwProcessId) +
                                L" CTID " + std::to_wstring(procInfo.dwThreadId) + 
                                (outInfo->GetSuspended() ? L" CSUSPENDED" : L"") +
                                (settings.suspendParents ? L" PSUSPENDED" : L"") + L"\n").c_str(), &messageStr) != S_OK)
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

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnEmbeddedBreakpointHitReceived(
    _In_ DkmThread*                 pThread,
    _In_opt_ DkmInstructionAddress* pInstructionAddress,
    _In_ bool                       ShowAsException,
    _In_ DkmEventDescriptorS*       pEventDescriptor)
{
    if(!settings.enabled) return S_OK;
    if(!settings.skipInitialBreakpoint) return S_OK;

    logFile << "On OnEmbeddedBreakpointHitReceived (Debugger PID " << GetCurrentProcessId() << ")\n";

    // The initial breakpoint is in ntdll.dll!LdrpDoDebuggerBreak()
    if(DkmString::CompareOrdinalIgnoreCase(pInstructionAddress->ModuleInstance()->Name(), L"ntdll.dll") != 0)  return S_OK;

    logFile << "  IN NTDLL\n";
    logFile.flush();

    logFile << " THREAD " << pThread << "\n";
    logFile.flush();

    if(pThread == nullptr) return S_FALSE;
    logFile << " PROCESS " << pThread->Process() << "\n";
    logFile.flush();
    if(pThread->Process() == nullptr) return S_FALSE;

    logFile << "  Has process\n";
    logFile.flush();

    CComPtr<ChildProcessItem> childInfo;
    pThread->Process()->GetDataItem(&childInfo);
    if(!childInfo)  return S_OK;
    
    logFile << "  Has child info\n";
    logFile << "    Passed Initial Breakpoint " <<  childInfo->GetPassedInitialBreakpoint() <<"\n";
    logFile.flush();

    // Skip if we passed the initial breakpoint already
    if(childInfo->GetPassedInitialBreakpoint()) return S_OK;

    // This has to be the initial breakpoint, so suppress handling it.
    pEventDescriptor->Suppress();

    // Set, that we passed the initial breakpoint for this process.
    childInfo->SetPassedInitialBreakpoint();

    logFile << "  Suppressed\n";
    logFile.flush();

    return S_OK;
}
