#include <string>
#include <cassert>
#include <thread>
#include <chrono>

#include <iostream> // TODO: remove

// #define WIN32_NO_STATUS
// # include <Windows.h>
// # include <winternl.h>
// #undef WIN32_NO_STATUS
// #include <ntstatus.h>

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include <vsdebugeng.h>
#include <vsdebugeng.templates.h>

#include "ChildDebuggerService.h"

#include "ntsuspend.h"

// #pragma comment(lib,"ntdll.lib")
// EXTERN_C NTSTATUS NTAPI NtResumeProcess(IN HANDLE ProcessHandle);


using namespace Microsoft::VisualStudio::Debugger;

// {0BB89D05-9EAD-4295-9A74-A241583DE420} (same as in vsdconfigxml filter)
static const GUID sourceId = { 0xbb89d05, 0x9ead, 0x4295, { 0x9a, 0x74, 0xa2, 0x41, 0x58, 0x3d, 0xe4, 0x20 } };

bool hasLoadedNtDll = false;

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

// void STDMETHODCALLTYPE CChildDebuggerService::OnComplete(
//         _In_ const Microsoft::VisualStudio::Debugger::Start::DkmDebugProcessRequestAsyncResult& Result
//         )
// {
    
// }

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

enum class CreateFunctionType
{
    CreateProcess,
    CreateProcessAsUser,
    CreateProcessWithToken,
    CreateProcessWithLogon
};


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


CChildDebuggerService::CChildDebuggerService()
{
    logFile.open(R"(childdebuglog.txt)", std::ios::out | std::ios::app);

    DkmString::Create(L"CreateProcessW", &createProcessFunctionNames[0]);
    DkmString::Create(L"CreateProcessA", &createProcessFunctionNames[1]);
    // DkmString::Create(L"CreateProcessAsUserW", &createProcessFunctionNames[2]);
    // DkmString::Create(L"CreateProcessAsUserA", &createProcessFunctionNames[3]);
    // DkmString::Create(L"CreateProcessWithTokenW", &createProcessFunctionNames[4]);
    // DkmString::Create(L"CreateProcessWithLogonW", &createProcessFunctionNames[5]);

    // attachCompleted.Attach(new AttachCompletedRoutine());
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::SendLower(
        DkmCustomMessage* pCustomMessage,
        DkmCustomMessage** ppReplyMessage)
{
    
    logFile << "CUSTOM MESSAGE:\n";
    logFile.flush();
    
    return S_OK;
}

struct CreateProcessWStack
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

UINT64 lastProcessInformation = 0;

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnRuntimeBreakpoint(
    Breakpoints::DkmRuntimeBreakpoint* pRuntimeBreakpoint,
    DkmThread* pThread,
    bool HasException,
    DkmEventDescriptorS* pEventDescriptor)
{
    logFile << "OnRuntimeBreakpoint:\n";
    logFile.flush();

    HRESULT hr;

    CComPtr<CreateInInfo> inInfo;
    hr = pRuntimeBreakpoint->GetDataItem(&inInfo);

    if(inInfo)
    {
        logFile << "  Start CreateProcess: W " << inInfo->GetIsUnicode() << " Func " << (int)inInfo->GetFunctionType() << "\n";
        logFile.flush();

        assert(inInfo->GetIsUnicode()); // Not yet implemented
        assert(inInfo->GetFunctionType() == CreateFunctionType::CreateProcess); // Not yet implemented

        UINT64 returnAddress;
        UINT64 frameBase;
        UINT64 vframe;
        hr = pThread->GetCurrentFrameInfo(&returnAddress, &frameBase, &vframe);

        CONTEXT context;
        hr = pThread->GetContext(CONTEXT_CONTROL | CONTEXT_INTEGER, &context, sizeof(CONTEXT));

        CreateProcessWStack stack;
        hr = pThread->Process()->ReadMemory(context.Rsp, DkmReadMemoryFlags::None, &stack, sizeof(CreateProcessWStack), nullptr);

        CAutoDkmArray<BYTE> applicationNameArray;
        hr = pThread->Process()->ReadMemoryString(context.Rcx, DkmReadMemoryFlags::None, 2, 0x8000, &applicationNameArray);
        const auto applicationName = reinterpret_cast<wchar_t*>(applicationNameArray.Members);

        logFile << "  APP " << (applicationName ? utf8_encode(applicationName) : "") << "\n";
        logFile.flush();

        CAutoDkmArray<BYTE> commandLineArray;
        hr = pThread->Process()->ReadMemoryString(context.Rdx, DkmReadMemoryFlags::None, 2, 0x8000, &commandLineArray);
        const auto commandLine = reinterpret_cast<wchar_t*>(commandLineArray.Members);

        logFile << "  CL " << (commandLine ? utf8_encode(commandLine) : "") << "\n";
        logFile.flush();

        CComPtr<DkmInstructionAddress> address;
        hr = pThread->Process()->CreateNativeInstructionAddress(returnAddress, &address);

        bool suspended = false;
        if((stack.dwCreationFlags & CREATE_SUSPENDED) == 0)
        {
            suspended = true;
            const auto newFlags = stack.dwCreationFlags | CREATE_SUSPENDED;

            CAutoDkmArray<BYTE> newFlagsBytes;
            DkmAllocArray(sizeof(stack.dwCreationFlags), &newFlagsBytes);
            memcpy(newFlagsBytes.Members, &newFlags, sizeof(stack.dwCreationFlags));
            hr = pThread->Process()->WriteMemory(context.Rsp + offsetof(CreateProcessWStack, dwCreationFlags), newFlagsBytes);
            
            logFile << "  Force suspended start\n";
            logFile.flush();
        }

        CComPtr<CreateOutInfo> outInfo;
        outInfo.Attach(new CreateOutInfo(stack.lpProcessInformation, suspended));

        CComPtr<Breakpoints::DkmRuntimeInstructionBreakpoint> breakpoint;
        hr = Breakpoints::DkmRuntimeInstructionBreakpoint::Create(sourceId, nullptr, address, false, outInfo, &breakpoint);

        hr = breakpoint->Enable();
    }
    else
    {
        logFile << "  Finish CreateProcess" << "\n";
        logFile.flush();

        CComPtr<CreateOutInfo> outInfo;
        pRuntimeBreakpoint->GetDataItem(&outInfo);

        PROCESS_INFORMATION procInfo;
        hr = pThread->Process()->ReadMemory(outInfo->GetProcessInformationAddress(), DkmReadMemoryFlags::None, &procInfo, sizeof(PROCESS_INFORMATION), nullptr);

        CComPtr<DkmString> messageStr;
        hr = DkmString::Create((L"ChildProcessDebugger: attach to child PID " + std::to_wstring(procInfo.dwProcessId) + (outInfo->GetSuspended() ? L" SUSPENDED" : L" RUNNING") + L"\n").c_str(), &messageStr);
        
        logFile << "  PROC " << procInfo.dwProcessId << "\n";
        logFile.flush();

        CComPtr<DkmUserMessage> message;
        hr = DkmUserMessage::Create(pThread->Connection(), pThread->Process(), DkmUserMessageOutputKind::UnfilteredOutputWindowMessage, messageStr, MB_OK, S_OK, &message);

        hr = message->Post();

        UINT32 pExternalSuspensionCount;
        pThread->Suspend(true, &pExternalSuspensionCount);

        // if(true)//outInfo->GetSuspended())
        // {
        //     // const auto procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId);

        //     const auto threadHandle = OpenThread(PROCESS_ALL_ACCESS, FALSE, procInfo.dwThreadId);

        //     ResumeThread(threadHandle);

        //     CloseHandle(threadHandle);
        // }

        // pRuntimeBreakpoint->Close();

        // CustomMessage: Not implemented?
        // {
        //     CComPtr<DkmCustomMessage> message;
        //     hr = DkmCustomMessage::Create(pThread->Connection(), pThread->Process(), sourceId, 0, nullptr, nullptr, nullptr, &message);

        //     CComPtr<DkmCustomMessage> reply;
        //     hr = message->SendHigher(&reply);
            
        //     CComPtr<DkmCustomMessage> reply2;
        //     hr = message->SendLower(&reply2);

        //     CAutoDkmArray<DefaultPort::DkmProductionConnection*> productionConnections;
        //     hr = pThread->Connection()->GetProductionConnections(&productionConnections);

        //     hr = message->SendToVsService(sourceId, true);
        // }

        // DkmDebugProcessRequest: Not implemented?
        // {
        //     const auto procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

        //     FILETIME creationTime;
        //     FILETIME exitTime;
        //     FILETIME kernelTime;
        //     FILETIME userTime;
        //     const auto timeSuccess = GetProcessTimes(procHandle, &creationTime, &exitTime, &kernelTime, &userTime);

        //     const auto startTime = (UINT64(creationTime.dwHighDateTime)<<32) | UINT64(creationTime.dwLowDateTime);

        //     wchar_t exeName[MAX_PATH];
        //     DWORD pathSize = MAX_PATH;
        //     const auto exeNameSuccess = QueryFullProcessImageNameW(procHandle, 0, exeName, &pathSize);
        //     if(!exeNameSuccess)
        //     {
        //         const auto exeNameSuccess2 = QueryFullProcessImageNameW(procHandle, PROCESS_NAME_NATIVE, exeName, &pathSize);
        //     }

        //     CComPtr<DkmString> exeNameStr;
        //     hr = DkmString::Create(exeName, &exeNameStr);

        //     CComPtr<Start::DkmDebugProcessRequest> request;
        //     hr = Start::DkmDebugProcessRequest::Create(processId, startTime, pThread->Process(), exeNameStr, nullptr, Start::DkmDebugProcessRequestFlags::None, &request);

        //     CComPtr<DkmWorkList> workList;
        //     hr = DkmWorkList::Create(nullptr, &workList);

        //     hr = request->Send(workList, this);
        // }
    }

    return S_OK;
}

    
HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnModuleInstanceLoad(
    DkmModuleInstance* pModuleInstance,
    DkmWorkList* pWorkList,
    DkmEventDescriptorS* pEventDescriptor)
{
    HRESULT hr;

    // logFile << "OnModuleInstanceLoad:\n";
    // logFile << "  " << utf8_encode(pModuleInstance->Name()->Value()) << "\n";
    // logFile << "  " << utf8_encode(pModuleInstance->FullName()->Value()) << "\n";
    // logFile.flush();

    auto* const nativeModuleInstance = Native::DkmNativeModuleInstance::TryCast(pModuleInstance);

    if(nativeModuleInstance == nullptr) return S_OK;

    // logFile << "  is native\n";
    // logFile.flush();

    if(DkmString::CompareOrdinalIgnoreCase(pModuleInstance->Name(), L"kernel32.dll") != 0 &&
    //    DkmString::CompareOrdinalIgnoreCase(pModuleInstance->Name(), L"kernelbase.dll") != 0 &&
       DkmString::CompareOrdinalIgnoreCase(pModuleInstance->Name(), L"advapi32.dll") != 0)
    {
        return S_OK;
    }

    for(auto& functionName : createProcessFunctionNames)
    {
        if(DkmString::IsNullOrEmpty(functionName)) continue;

        CComPtr<Native::DkmNativeInstructionAddress> address;
        hr = nativeModuleInstance->FindExportName(functionName, true, &address);
        if(hr != S_OK) continue;

        logFile << "OnModuleInstanceLoad (" << GetCurrentProcessId() << ")\n";
        logFile << "  " << utf8_encode(pModuleInstance->Name()->Value()) << "\n";
        logFile << "  BA " << pModuleInstance->BaseAddress() << "\n";
        logFile << "  => HAS ADDRESS " << utf8_encode(functionName->Value()) << " @" << address->RVA() << "\n";
        logFile.flush();

        

        // TODO: attach necessary data to breakpoint

        auto functionType = CreateFunctionType::CreateProcess;

        CComPtr<CreateInInfo> inInfo;
        inInfo.Attach(new CreateInInfo(functionName->Value()[functionName->Length() - 1] == 'W', functionType));

        CComPtr<Breakpoints::DkmRuntimeInstructionBreakpoint> breakpoint;
        hr = Breakpoints::DkmRuntimeInstructionBreakpoint::Create(sourceId, nullptr, address, false, inInfo, &breakpoint);
        if(hr != S_OK) continue;

        // logFile << "  => HAS BREAKPOINT\n";
        // logFile.flush();
        
        hr = breakpoint->Enable();
        if(hr != S_OK) continue;
        
        // logFile << "  => ENABLED\n";
        // logFile.flush();

        // breakpoints.push_back(breakpoint);
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnProcessCreate(
        _In_ DkmProcess* pProcess,
        _In_ DkmWorkList* pWorkList,
        _In_ DkmEventDescriptor* pEventDescriptor)
{
    if(pProcess->LivePart() == nullptr) return S_OK;

    logFile << "OnProcessCreate (" << GetCurrentProcessId() << ")\n";
    logFile << "  " << utf8_encode(pProcess->Path()->Value()) << "\n";
    logFile << "  PID " << pProcess->LivePart()->Id << "\n";
    logFile.flush();

    HRESULT hr;

    CAutoDkmArray<DkmThread*> threads;
    hr = pProcess->GetThreads(&threads);

    logFile << "  THREADS " << hr << " " << threads.Length << "\n";
    logFile.flush();

    const auto processHandle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pProcess->LivePart()->Id);

    logFile << "  HANDLE " << processHandle << "\n";
    logFile.flush();

    if(!hasLoadedNtDll)
    {
        const auto status = ImportNtDll();
        if(!status)
        {
            CloseHandle(processHandle);
            return S_OK;
        }
        hasLoadedNtDll = true;
    }

    const auto status = NT_Resume(processHandle);

    logFile << "  STATUS " << status << "\n";
    logFile.flush();

    CloseHandle(processHandle);


    // for(int i = 0; i < threads.Length; ++i)
    // {
    //     auto* const thread = threads.Members[i];
    //     if(thread->SystemPart() == nullptr) continue;
    //     if(!thread->IsMainThread()) continue;
        
    //     logFile << "  RESUME MAIN THREAD " << pProcess->LivePart()->Id << "\n";
    //     logFile.flush();

    //     const auto threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread->SystemPart()->Id);
    //     ResumeThread(threadHandle);
    //     CloseHandle(threadHandle);
    // }
    
    return S_OK;
}
