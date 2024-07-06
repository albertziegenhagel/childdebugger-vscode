#pragma once

#include <array>
#include <vector>
#include <string>

#include <fstream>

#include "ChildDebugger.contract.h"

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

public:

    virtual HRESULT STDMETHODCALLTYPE OnModuleInstanceLoad(
        _In_ Microsoft::VisualStudio::Debugger::DkmModuleInstance* pModuleInstance,
        _In_ Microsoft::VisualStudio::Debugger::DkmWorkList* pWorkList,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* pEventDescriptor) override;

    virtual HRESULT STDMETHODCALLTYPE OnRuntimeBreakpoint(
        _In_ Microsoft::VisualStudio::Debugger::Breakpoints::DkmRuntimeBreakpoint* pRuntimeBreakpoint,
        _In_ Microsoft::VisualStudio::Debugger::DkmThread* pThread,
        _In_ bool HasException,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptorS* pEventDescriptor) override;

    virtual HRESULT STDMETHODCALLTYPE OnProcessCreate(
        _In_ Microsoft::VisualStudio::Debugger::DkmProcess* pProcess,
        _In_ Microsoft::VisualStudio::Debugger::DkmWorkList* pWorkList,
        _In_ Microsoft::VisualStudio::Debugger::DkmEventDescriptor* pEventDescriptor) override;

private:
    std::ofstream logFile;
    std::array<CComPtr<Microsoft::VisualStudio::Debugger::DkmString>, 6> createProcessFunctionNames;
    std::vector<std::string> no_suspend_exe_names;
};

OBJECT_ENTRY_AUTO(CChildDebuggerService::ClassId, CChildDebuggerService)
