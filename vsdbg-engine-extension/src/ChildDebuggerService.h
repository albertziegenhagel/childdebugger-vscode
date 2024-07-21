#pragma once

#include <array>
#include <optional>
#include <string>
#include <vector>

#include <fstream>

#include "ChildDebugger.contract.h"

struct ProcessConfig
{
    std::optional<std::wstring> applicationName = std::nullopt;
    std::optional<std::wstring> commandLine     = std::nullopt;
    bool                        attach          = true;
};

struct ChildDebuggerSettings
{
    bool enabled = false;

    bool suspendChildren = true;
    bool suspendParents  = true;

    bool skipInitialBreakpoint = true;

    std::vector<ProcessConfig> processConfigs;
    bool                       attachOthers = true;
};

class ATL_NO_VTABLE CChildDebuggerService :
    public CChildDebuggerServiceContract,
    public CComObjectRootEx<CComMultiThreadModel>,
    public CComCoClass<CChildDebuggerService, &CChildDebuggerServiceContract::ClassId>
{
protected:
    CChildDebuggerService();
    ~CChildDebuggerService() = default;

public:
    DECLARE_NO_REGISTRY();
    DECLARE_NOT_AGGREGATABLE(CChildDebuggerService);

    CChildDebuggerService(CChildDebuggerService&)             = delete;
    CChildDebuggerService(CChildDebuggerService&&)            = delete;
    CChildDebuggerService& operator=(CChildDebuggerService&)  = delete;
    CChildDebuggerService& operator=(CChildDebuggerService&&) = delete;

public:
    virtual HRESULT STDMETHODCALLTYPE SendLower(
        Microsoft::VisualStudio::Debugger::DkmCustomMessage*  custom_message,
        Microsoft::VisualStudio::Debugger::DkmCustomMessage** ppReplyMessage) override;

    virtual HRESULT STDMETHODCALLTYPE OnModuleInstanceLoad(
        _In_ Microsoft::VisualStudio::Debugger::DkmModuleInstance* module_instance,
        _In_ Microsoft::VisualStudio::Debugger::DkmWorkList* pWorkList,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* pEventDescriptor) override;

    virtual HRESULT STDMETHODCALLTYPE OnRuntimeBreakpoint(
        _In_ Microsoft::VisualStudio::Debugger::Breakpoints::DkmRuntimeBreakpoint* runtime_breakpoint,
        _In_ Microsoft::VisualStudio::Debugger::DkmThread* pThread,
        _In_ bool                                          HasException,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* pEventDescriptor) override;

    virtual HRESULT STDMETHODCALLTYPE OnEmbeddedBreakpointHitReceived(
        _In_ Microsoft::VisualStudio::Debugger::DkmThread* pThread,
        _In_opt_ Microsoft::VisualStudio::Debugger::DkmInstructionAddress* instruction_address,
        _In_ bool                                                          ShowAsException,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* event_descriptor) override;

private:
    ChildDebuggerSettings                                                settings;
    std::ofstream                                                        logFile;
    std::array<CComPtr<Microsoft::VisualStudio::Debugger::DkmString>, 6> createProcessFunctionNames;
};

OBJECT_ENTRY_AUTO(CChildDebuggerService::ClassId, CChildDebuggerService)
