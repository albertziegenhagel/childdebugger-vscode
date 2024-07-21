#pragma once

#include <array>
#include <optional>
#include <string>
#include <vector>

#include <fstream>

#include "ChildDebugger.contract.h"

struct ProcessConfig
{
    std::optional<std::wstring> application_name = std::nullopt;
    std::optional<std::wstring> command_line     = std::nullopt;
    bool                        attach           = true;
};

struct ChildDebuggerSettings
{
    bool enabled = false;

    bool suspend_children = true;
    bool suspend_parents  = true;

    bool skip_initial_breakpoint = true;

    std::vector<ProcessConfig> process_configs;
    bool                       attach_others = true;
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
    HRESULT STDMETHODCALLTYPE SendLower(
        Microsoft::VisualStudio::Debugger::DkmCustomMessage*  custom_message,
        Microsoft::VisualStudio::Debugger::DkmCustomMessage** reply_message) override;

    HRESULT STDMETHODCALLTYPE OnModuleInstanceLoad(
        _In_ Microsoft::VisualStudio::Debugger::DkmModuleInstance* module_instance,
        _In_ Microsoft::VisualStudio::Debugger::DkmWorkList* work_list,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* event_descriptor) override;

    HRESULT STDMETHODCALLTYPE OnRuntimeBreakpoint(
        _In_ Microsoft::VisualStudio::Debugger::Breakpoints::DkmRuntimeBreakpoint* runtime_breakpoint,
        _In_ Microsoft::VisualStudio::Debugger::DkmThread* thread,
        _In_ bool                                          has_exception,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* event_descriptor) override;

    HRESULT STDMETHODCALLTYPE OnEmbeddedBreakpointHitReceived(
        _In_ Microsoft::VisualStudio::Debugger::DkmThread* thread,
        _In_opt_ Microsoft::VisualStudio::Debugger::DkmInstructionAddress* instruction_address,
        _In_ bool                                                          show_as_exception,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* event_descriptor) override;

private:
    ChildDebuggerSettings                                                settings_;
    std::ofstream                                                        log_file_;
    std::array<CComPtr<Microsoft::VisualStudio::Debugger::DkmString>, 6> create_process_function_names_;
};

OBJECT_ENTRY_AUTO(CChildDebuggerService::ClassId, CChildDebuggerService)
