#pragma once

#include <vsdebugeng.h>

#include "CreateFunctionType.hpp"

// Base class for breakpoint information classes.
template<typename Interface>
class BaseObject : public Interface
{
    volatile LONG ref_count_;

public:
    virtual ~BaseObject() = default;

    BaseObject() = default;

    BaseObject(BaseObject&)             = delete;
    BaseObject(BaseObject&&)            = delete;
    BaseObject& operator=(BaseObject&)  = delete;
    BaseObject& operator=(BaseObject&&) = delete;

    ULONG __stdcall AddRef() override
    {
        return (ULONG)InterlockedIncrement(&ref_count_);
    }
    ULONG __stdcall Release() override
    {
        auto result = (ULONG)InterlockedDecrement(&ref_count_);
        if(result == 0)
        {
            delete this;
        }
        return result;
    }
    HRESULT __stdcall QueryInterface(REFIID riid, _Deref_out_ void** ppv) override
    {
        if(riid == __uuidof(IUnknown))
        {
            *ppv = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }
        // This example is implementing the optional interface IDkmDisposableDataItem
        if(riid == __uuidof(Microsoft::VisualStudio::Debugger::IDkmDisposableDataItem))
        {
            *ppv = static_cast<Microsoft::VisualStudio::Debugger::IDkmDisposableDataItem*>(this);
            AddRef();
            return S_OK;
        }

        *ppv = nullptr;
        return E_NOINTERFACE;
    }
};

// Class holding additional information for breakpoints to be triggered on
// a call to any of the process creation functions.
class __declspec(uuid("{1483C347-BDAD-4626-B33F-D16970542239}")) CreateInInfo :
    public BaseObject<Microsoft::VisualStudio::Debugger::IDkmDisposableDataItem>
{
    bool               isUnicode_;
    CreateFunctionType functionType_;

public:
    explicit CreateInInfo(bool is_unicode, CreateFunctionType function_type) :
        isUnicode_(is_unicode),
        functionType_(function_type)
    {}

    CreateInInfo(CreateInInfo&)             = delete;
    CreateInInfo(CreateInInfo&&)            = delete;
    CreateInInfo& operator=(CreateInInfo&)  = delete;
    CreateInInfo& operator=(CreateInInfo&&) = delete;

    ~CreateInInfo() override = default;

    HRESULT __stdcall OnClose() override
    {
        return S_OK;
    }

    [[nodiscard]] bool get_is_unicode() const
    {
        return isUnicode_;
    }

    [[nodiscard]] CreateFunctionType get_function_type() const
    {
        return functionType_;
    }
};

// Class holding additional information for breakpoints to be triggered when
// we return from a  call to any of the process creation functions.
class __declspec(uuid("{F1AB4299-C3EB-47C5-83B7-813E28B9DA89}")) CreateOutInfo :
    public BaseObject<Microsoft::VisualStudio::Debugger::IDkmDisposableDataItem>
{
    UINT64 lpProcessInformation_;
    bool   suspended_;

public:
    explicit CreateOutInfo(UINT64 process_information, bool suspended) :
        lpProcessInformation_(process_information),
        suspended_(suspended)
    {}

    CreateOutInfo(CreateOutInfo&)             = delete;
    CreateOutInfo(CreateOutInfo&&)            = delete;
    CreateOutInfo& operator=(CreateOutInfo&)  = delete;
    CreateOutInfo& operator=(CreateOutInfo&&) = delete;

    ~CreateOutInfo() override = default;

    HRESULT __stdcall OnClose() override
    {
        return S_OK;
    }

    [[nodiscard]] UINT64 get_process_information_address() const
    {
        return lpProcessInformation_;
    }

    [[nodiscard]] bool get_suspended() const
    {
        return suspended_;
    }
};

class ATL_NO_VTABLE __declspec(uuid("{0709D0FC-76B1-44E8-B781-E8C43461CFAC}")) ChildProcessDataItem :
    public IUnknown,
    public CComObjectRootEx<CComMultiThreadModel>
{
    bool passedInitialBreakpoint_{false};

public:
    explicit ChildProcessDataItem() = default;

    ~ChildProcessDataItem() = default;

    ChildProcessDataItem(ChildProcessDataItem&)             = delete;
    ChildProcessDataItem(ChildProcessDataItem&&)            = delete;
    ChildProcessDataItem& operator=(ChildProcessDataItem&)  = delete;
    ChildProcessDataItem& operator=(ChildProcessDataItem&&) = delete;

    [[nodiscard]] bool get_passed_initial_breakpoint() const
    {
        return passedInitialBreakpoint_;
    }

    void set_passed_initial_breakpoint()
    {
        passedInitialBreakpoint_ = true;
    }

protected:
    // NOLINTNEXTLINE(bugprone-reserved-identifier, readability-identifier-naming)
    HRESULT _InternalQueryInterface(REFIID riid, void** object)
    {
        if(object == nullptr)
            return E_POINTER;

        if(riid == __uuidof(IUnknown))
        {
            *object = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }

        *object = nullptr;
        return E_NOINTERFACE;
    }
};
