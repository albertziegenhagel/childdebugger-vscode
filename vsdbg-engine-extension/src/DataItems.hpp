#pragma once

#include <vsdebugeng.h>

#include "CreateFunctionType.hpp"

// Class holding additional information for breakpoints to be triggered on
// a call to any of the process creation functions.
class __declspec(uuid("{1483C347-BDAD-4626-B33F-D16970542239}")) CreateInInfoDataItem :
    public IUnknown,
    public CComObjectRootEx<CComMultiThreadModel>
{
    bool               isUnicode_;
    CreateFunctionType functionType_;

public:
    explicit CreateInInfoDataItem() = default;

    CreateInInfoDataItem(CreateInInfoDataItem&)             = delete;
    CreateInInfoDataItem(CreateInInfoDataItem&&)            = delete;
    CreateInInfoDataItem& operator=(CreateInInfoDataItem&)  = delete;
    CreateInInfoDataItem& operator=(CreateInInfoDataItem&&) = delete;

    ~CreateInInfoDataItem() = default;

    void initialize(bool is_unicode, CreateFunctionType function_type)
    {
        isUnicode_    = is_unicode;
        functionType_ = function_type;
    }

    [[nodiscard]] bool get_is_unicode() const
    {
        return isUnicode_;
    }

    [[nodiscard]] CreateFunctionType get_function_type() const
    {
        return functionType_;
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

// Class holding additional information for breakpoints to be triggered when
// we return from a  call to any of the process creation functions.
class __declspec(uuid("{F1AB4299-C3EB-47C5-83B7-813E28B9DA89}")) CreateOutInfoDataItem :
    public IUnknown,
    public CComObjectRootEx<CComMultiThreadModel>
{
    UINT64 lpProcessInformation_;
    bool   suspended_;

public:
    explicit CreateOutInfoDataItem() = default;

    void initialize(UINT64 process_information, bool suspended)
    {
        lpProcessInformation_ = process_information;
        suspended_            = suspended;
    }

    CreateOutInfoDataItem(CreateOutInfoDataItem&)             = delete;
    CreateOutInfoDataItem(CreateOutInfoDataItem&&)            = delete;
    CreateOutInfoDataItem& operator=(CreateOutInfoDataItem&)  = delete;
    CreateOutInfoDataItem& operator=(CreateOutInfoDataItem&&) = delete;

    ~CreateOutInfoDataItem() = default;

    [[nodiscard]] UINT64 get_process_information_address() const
    {
        return lpProcessInformation_;
    }

    [[nodiscard]] bool get_suspended() const
    {
        return suspended_;
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
