
#include "ChildDebuggerService.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <psapi.h>

#include <vsdebugeng.h>
#include <vsdebugeng.templates.h>

#include "nlohmann/json.hpp"

#include "CreateFunctionType.hpp"
#include "CustomMessageType.hpp"
#include "DataItems.hpp"
#include "FunctionCallContext.hpp"
#include "SystemUtils.hpp"
#include "UnicodeUtils.hpp"

using namespace Microsoft::VisualStudio::Debugger;

// Source ID for breakpoints that we create for child process debugging.
// This allows this extension to only get notified on breakpoints that it created itself.
// {0BB89D05-9EAD-4295-9A74-A241583DE420} (same as in vsdconfigxml filter)
static const GUID source_id = {
    0x0bb8'9d05, 0x9ead, 0x4295, {0x9a, 0x74, 0xa2, 0x41, 0x58, 0x3d, 0xe4, 0x20}
};

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
    return utf8_to_utf16(str);
}

HRESULT read_string_from_memory_at(
    DkmProcess*         process,
    DWORD64             address,
    bool                is_unicode,
    CComPtr<DkmString>& result)
{
    if(address == 0) return S_OK;

    CAutoDkmArray<BYTE> bytes;
    if(process->ReadMemoryString(address, DkmReadMemoryFlags::None, is_unicode ? 2 : 1, 0x8000, &bytes) != S_OK)
    {
        return S_FALSE;
    }

    if(is_unicode)
    {
        return DkmString::Create(reinterpret_cast<const wchar_t*>(bytes.Members), &result);
    }

    return DkmString::Create(CP_ACP, reinterpret_cast<const char*>(bytes.Members), bytes.Length, &result);
}

bool check_attach_to_process(
    const ChildDebuggerSettings& settings,
    std::ofstream&               log_file,
    const CComPtr<DkmString>&    application_name,
    const CComPtr<DkmString>&    command_line)
{
    if(!application_name && !command_line) return settings.attach_others;

    for(const auto& config : settings.process_configs)
    {
        log_file << "  Check process config: "
                 << "\n";
        log_file << "    applicationName: " << (config.application_name ? utf16_to_utf8(*config.application_name) : "<EMPTY>") << "\n";
        log_file << "    commandLine: " << (config.command_line ? utf16_to_utf8(*config.command_line) : "<EMPTY>") << "\n";

        // Skip invalid, empty config
        if(!config.application_name && !config.command_line) continue;

        if(config.application_name)
        {
            // We failed to extract the application name: skip
            if(!application_name) continue;

            // The current application name is shorter than the config: it can not match, so skip
            if(application_name->Length() < config.application_name->size()) continue;

            const auto application_name_view = std::wstring_view(application_name->Value(), application_name->Length());

            const auto application_name_final_part = application_name_view.substr(application_name->Length() - config.application_name->size(), config.application_name->size());

            // NOTE: we can assume `applicationNameFinalPart.data()` to be null-terminated because it points to the end of the original string.
            if(DkmString::CompareOrdinalIgnoreCase(application_name_final_part.data(), config.application_name->c_str()) != 0) continue;
        }

        if(config.command_line)
        {
            // We failed to extract the command line: skip
            if(!command_line) continue;

            const auto command_line_view = std::wstring_view(command_line->Value(), command_line->Length());

            if(!command_line_view.contains(*config.command_line)) continue;
        }

        log_file << "    matched. attach: " << config.attach << "\n";
        log_file.flush();
        return config.attach;
    }

    log_file << "  No process config match. attach: " << settings.attach_others << "\n";
    log_file.flush();
    return settings.attach_others;
}

template<typename FunctionSignature>
HRESULT load_function_context(std::ofstream&                               log_file,
                              DkmThread&                                   thread,
                              BasicFunctionCallContext<FunctionSignature>& context)
{
    const UINT32 context_flags = CONTEXT_CONTROL | CONTEXT_INTEGER; // NOLINT(misc-redundant-expression)
    if(thread.GetContext(context_flags, &context.registers, sizeof(context.registers)) != S_OK)
    {
        log_file << "  FAILED to retrieve thread register context.\n";
        log_file.flush();
        return S_FALSE;
    }

    const auto stack_pointer = get_stack_pointer(context.registers);

    if(thread.Process()->ReadMemory(stack_pointer, DkmReadMemoryFlags::None, context.stack.data(), context.stack.size(), nullptr) != S_OK)
    {
        log_file << "  FAILED to read stack.\n";
        log_file.flush();
        return S_FALSE;
    }

    return S_OK;
}

template<typename FunctionSignature>
HRESULT store_function_context(std::ofstream&                               log_file,
                               DkmThread&                                   thread,
                               BasicFunctionCallContext<FunctionSignature>& context)
{
    if(context.registers_changed)
    {
        CAutoDkmArray<BYTE> register_bytes;
        DkmAllocArray(sizeof(context.registers), &register_bytes);
        std::memcpy(register_bytes.Members, &context.registers, sizeof(context.registers));
        if(thread.SetContext(register_bytes) != S_OK)
        {
            log_file << "  FAILED to write thread register context.\n";
            log_file.flush();
            return S_FALSE;
        }
    }

    if(context.stack_changed)
    {
        const auto stack_pointer = get_stack_pointer(context.registers);

        CAutoDkmArray<BYTE> stack_bytes;
        DkmAllocArray(context.stack.size(), &stack_bytes);
        std::memcpy(stack_bytes.Members, context.stack.data(), context.stack.size());
        if(thread.Process()->WriteMemory(stack_pointer, stack_bytes) != S_OK)
        {
            log_file << "  FAILED to write stack memory.\n";
            log_file.flush();
            return S_FALSE;
        }
    }

    return S_OK;
}

template<typename FunctionContextType>
HRESULT handle_call_to_create_process(
    const ChildDebuggerSettings& settings,
    std::ofstream&               log_file,
    DkmThread&                   thread,
    bool                         is_unicode)
{
    FunctionContextType function_call_context;
    load_function_context(log_file, thread, function_call_context);

    // Extract the application name from the passed arguments.
    // Assuming x64 calling conventions, the pointer to the string in memory is stored in the
    // RCX register for `CreateProcessA` and `CreateProcessW`.
    CComPtr<DkmString> application_name;
    if(read_string_from_memory_at(thread.Process(), function_call_context.get_lpApplicationName(), is_unicode, application_name) != S_OK)
    {
        log_file << "  FAILED to read application name argument.\n";
        log_file.flush();
        return S_FALSE;
    }
    if(application_name)
    {
        log_file << "  APP " << utf16_to_utf8(application_name->Value()) << "\n";
        log_file.flush();
    }

    // Extract the command line from the passed arguments.
    // Assuming x64 calling conventions, the pointer to the string in memory is stored in the
    // RDX register for `CreateProcessA` and `CreateProcessW`.
    CComPtr<DkmString> command_line;
    if(read_string_from_memory_at(thread.Process(), function_call_context.get_lpCommandLine(), is_unicode, command_line) != S_OK)
    {
        log_file << "  FAILED to read command line argument.\n";
        log_file.flush();
        return S_FALSE;
    }
    if(command_line)
    {
        log_file << "  CL " << utf16_to_utf8(command_line->Value()) << "\n";
        log_file.flush();
    }

    if(!check_attach_to_process(settings, log_file, application_name, command_line)) return S_OK;

    const auto creation_flags = function_call_context.get_dwCreationFlags();
    log_file << "  dwCreationFlags=" << creation_flags << "\n";

    // If want to suspend the child process and it is not already requested to be suspended
    // originally, we enforce a suspended process creation.
    bool forced_suspension = false;
    if((creation_flags & CREATE_SUSPENDED) != 0)
    {
        log_file << "  Originally requested suspended start\n";
        log_file.flush();
    }
    else if(settings.suspend_children)
    {
        function_call_context.set_dwCreationFlags(creation_flags | CREATE_SUSPENDED);
        forced_suspension = true;
        log_file << "  Force suspended start\n";
        log_file.flush();
    }
    else
    {
        log_file << "  Skip suspended start\n";
        log_file.flush();
    }

    store_function_context(log_file, thread, function_call_context);

    CComPtr<DkmInstructionAddress> address;
    if(thread.Process()->CreateNativeInstructionAddress(function_call_context.get_return_address(), &address) != S_OK)
    {
        log_file << "  FAILED to create native instruction address from function return address.\n";
        log_file.flush();
        return S_FALSE;
    }

    // Create a new breakpoint to be triggered when the child process creation is done.
    CComPtr<CreateOutInfo> out_info;
    out_info.Attach(new CreateOutInfo(function_call_context.get_lpProcessInformation(), forced_suspension));

    CComPtr<Breakpoints::DkmRuntimeInstructionBreakpoint> breakpoint;
    if(Breakpoints::DkmRuntimeInstructionBreakpoint::Create(source_id, nullptr, address, false, out_info, &breakpoint) != S_OK)
    {
        log_file << "  FAILED to create breakpoint!\n";
        log_file.flush();
        return S_FALSE;
    }

    if(breakpoint->Enable() != S_OK)
    {
        log_file << "  FAILED to enable breakpoint!\n";
        log_file.flush();
        return S_FALSE;
    }

    return S_OK;
}

CChildDebuggerService::CChildDebuggerService()
{
    const auto* const log_file_name = "ChildDebugger.log";

    const auto root = get_current_module_path();

    const auto log_file_path = root ? (*root / log_file_name) : log_file_name;
    log_file_.open(log_file_path, std::ios::out | std::ios::app);

    DkmString::Create(L"CreateProcessW", &create_process_function_names_[0]);
    DkmString::Create(L"CreateProcessA", &create_process_function_names_[1]);
    DkmString::Create(L"CreateProcessAsUserW", &create_process_function_names_[2]);
    DkmString::Create(L"CreateProcessAsUserA", &create_process_function_names_[3]);
    DkmString::Create(L"CreateProcessWithTokenW", &create_process_function_names_[4]);
    DkmString::Create(L"CreateProcessWithLogonW", &create_process_function_names_[5]);
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::SendLower(
    DkmCustomMessage* custom_message,
    DkmCustomMessage** /*reply_message*/)
{
    log_file_ << "On CustomMessage (Debugger PID " << GetCurrentProcessId() << ")\n";
    log_file_ << "  MessageCode " << custom_message->MessageCode() << "\n";
    log_file_.flush();

    switch(CustomMessageType(custom_message->MessageCode()))
    {
    case CustomMessageType::settings:
    {
        if(custom_message->Parameter1() == nullptr || custom_message->Parameter1()->Type() != VT_BSTR) return S_FALSE;

        auto* const settings_str = custom_message->Parameter1()->Value().bstrVal;

        // TODO: if we can find a reasonably small JSON parser library that can handle UTF-16 encoded
        // strings, we can probably get rid of this transcoding.
        const auto utf8_settings_str = utf16_to_utf8(settings_str);

        try
        {
            const auto settings_json = nlohmann::json::parse(utf8_settings_str);

            settings_.suspend_parents         = try_get_or(settings_json, "suspendParents", true);
            settings_.suspend_children        = try_get_or(settings_json, "suspendChildren", true);
            settings_.skip_initial_breakpoint = try_get_or(settings_json, "skipInitialBreakpoint", true);
            settings_.attach_any              = try_get_or(settings_json, "attachAny", true);
            settings_.attach_others           = try_get_or(settings_json, "attachOthers", true);

            settings_.process_configs.clear();
            if(settings_json.count("processConfigs") > 0)
            {
                for(const auto& config_entry : settings_json.at("processConfigs"))
                {
                    settings_.process_configs.push_back(
                        ProcessConfig{
                            .application_name = try_get_optional_string(config_entry, "applicationName"),
                            .command_line     = try_get_optional_string(config_entry, "commandLine"),
                            .attach           = try_get_or(config_entry, "attach", true)});
                }
            }

            enabled_ = true;
        }
        catch(const nlohmann::json::parse_error& ex)
        {
            log_file_ << "  Failed to parse JSON settings: " << ex.what() << "\n";
            log_file_.flush();
        }
        log_file_ << "  suspendParents:        " << settings_.suspend_parents << "\n";
        log_file_ << "  suspendChildren:       " << settings_.suspend_children << "\n";
        log_file_ << "  skipInitialBreakpoint: " << settings_.skip_initial_breakpoint << "\n";
        log_file_ << "  attachAny:             " << settings_.attach_any << "\n";
        log_file_ << "  attachOthers:          " << settings_.attach_others << "\n";
        log_file_ << "  processConfigs:\n";
        for(const auto& config : settings_.process_configs)
        {
            log_file_ << "    applicationName:        " << (config.application_name ? utf16_to_utf8(*config.application_name) : "<EMPTY>") << "\n";
            log_file_ << "    commandLine:            " << (config.command_line ? utf16_to_utf8(*config.command_line) : "<EMPTY>") << "\n";
            log_file_ << "    attach:                 " << config.attach << "\n";
        }
        log_file_.flush();
    }
    break;
    case CustomMessageType::resume_child:
    case CustomMessageType::inform_child:
    {
        if(!enabled_) return S_OK;

        if(custom_message->Parameter1() == nullptr || custom_message->Parameter1()->Type() != VT_I4) return S_FALSE;
        if(custom_message->Parameter2() == nullptr || custom_message->Parameter2()->Type() != VT_I4) return S_FALSE;

        const auto process_id = custom_message->Parameter1()->Value().lVal;
        const auto thread_id  = custom_message->Parameter2()->Value().lVal;
        log_file_ << "  child PID " << process_id << "\n";
        log_file_ << "  child TID " << thread_id << "\n";

        CComPtr<DkmProcess> process;
        if(custom_message->Connection()->FindLiveProcess(process_id, &process) != S_OK)
        {
            log_file_ << "  Failed to find process\n";
            log_file_.flush();
            return S_FALSE;
        }

        CComObject<ChildProcessDataItem>* com_obj;
        if(auto hr = CComObject<ChildProcessDataItem>::CreateInstance(&com_obj); FAILED(hr))
        {
            log_file_ << "  Failed to create child process ComObject instance\n";
            log_file_.flush();
            return hr;
        }

        const CComPtr<ChildProcessDataItem> child_info(com_obj);
        if(auto hr = process->SetDataItem(DkmDataCreationDisposition::CreateNew, child_info); FAILED(hr))
        {
            log_file_ << "  Failed to set child process data item\n";
            log_file_.flush();
            return hr;
        }

        if(CustomMessageType(custom_message->MessageCode()) == CustomMessageType::resume_child)
        {
            auto* const thread_handle = OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id);
            if(thread_handle == nullptr)
            {
                log_file_ << "  Failed to open thread\n";
                log_file_.flush();
                return S_FALSE;
            }

            // Resume the thread.
            log_file_ << "  CALL ResumeThread\n";
            log_file_.flush();
            const auto suspend_count = ResumeThread(thread_handle);
            log_file_ << "  RESULT " << suspend_count << "\n";
            log_file_.flush();
            CloseHandle(thread_handle);
        }
    }
    break;
    case CustomMessageType::resume_parent:
    {
        if(!enabled_) return S_OK;

        if(custom_message->Parameter1() == nullptr || custom_message->Parameter1()->Type() != VT_I4) return S_FALSE;
        if(custom_message->Parameter2() == nullptr || custom_message->Parameter2()->Type() != VT_I4) return S_FALSE;

        const auto process_id = custom_message->Parameter1()->Value().lVal;
        const auto thread_id  = custom_message->Parameter2()->Value().lVal;
        log_file_ << "  parent PID " << process_id << "\n";
        log_file_ << "  parent TID " << thread_id << "\n";

        CComPtr<DkmProcess> process;
        if(custom_message->Connection()->FindLiveProcess(process_id, &process) != S_OK)
        {
            log_file_ << "  Failed to find process\n";
            log_file_.flush();
            return S_FALSE;
        }

        CComPtr<DkmThread> thread;
        if(process->FindSystemThread(thread_id, &thread) != S_OK)
        {
            log_file_ << "  Failed to find thread\n";
            log_file_.flush();
            return S_FALSE;
        }

        UINT32 external_suspension_count;
        if(thread->Resume(true, &external_suspension_count) != S_OK)
        {
            log_file_ << "  Failed to resume thread\n";
            log_file_.flush();
            return S_FALSE;
        }
    }
    break;
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnModuleInstanceLoad(
    DkmModuleInstance* module_instance,
    DkmWorkList* /*work_list*/,
    DkmEventDescriptorS* /*event_descriptor*/)
{
    if(!enabled_) return S_OK;
    if(!settings_.attach_any) return S_OK;

    // Check whether the loaded module is one of the Windows core DLLs that provide any of the Win32 API
    // functions for child process creation that we are interested in.

    // If it is not a native module, we are not interested (since the Windows core DLLs are native).
    auto* const native_module_instance = Native::DkmNativeModuleInstance::TryCast(module_instance);
    if(native_module_instance == nullptr) return S_OK;

    // kernel32.dll provides:
    //  - CreateProcessA / CreateProcessW
    // advapi32.dll provides:
    //  - CreateProcessAsUserA / CreateProcessAsUserW
    //  - CreateProcessWithTokenW
    //  - CreateProcessWithLogonW
    if(DkmString::CompareOrdinalIgnoreCase(module_instance->Name(), L"kernel32.dll") != 0 &&
       DkmString::CompareOrdinalIgnoreCase(module_instance->Name(), L"advapi32.dll") != 0)
    {
        return S_OK;
    }

    // Now, try to find any of the supported process creation functions in this module and create
    // a breakpoint for any that we find.
    for(auto& function_name : create_process_function_names_)
    {
        if(DkmString::IsNullOrEmpty(function_name)) continue;

        // Try to find the address of the current function in the module.
        CComPtr<Native::DkmNativeInstructionAddress> address;
        if(native_module_instance->FindExportName(function_name, true, &address) != S_OK) continue;

        log_file_ << "OnModuleInstanceLoad (Debugger PID " << GetCurrentProcessId() << ")\n";
        log_file_ << "  " << utf16_to_utf8(module_instance->Name()->Value()) << "\n";
        log_file_ << "  Base address " << module_instance->BaseAddress() << "\n";
        log_file_ << "  Function address " << utf16_to_utf8(function_name->Value()) << " @" << address->RVA() << "\n";
        log_file_.flush();

        // TODO: Simplify this:
        const auto function_type = [&function_name]() -> CreateFunctionType
        {
            if(std::wstring_view(function_name->Value(), function_name->Length()).starts_with(L"CreateProcessWithLogon"))
            {
                return CreateFunctionType::create_process_with_logon;
            }
            if(std::wstring_view(function_name->Value(), function_name->Length()).starts_with(L"CreateProcessWithToken"))
            {
                return CreateFunctionType::create_process_with_token;
            }
            if(std::wstring_view(function_name->Value(), function_name->Length()).starts_with(L"CreateProcessAsUser"))
            {
                return CreateFunctionType::create_process_as_user;
            }
            return CreateFunctionType::create_process;
        }();

        // Attach some information to the breakpoint about the function it has been generated for.
        CComPtr<CreateInInfo> in_info;
        in_info.Attach(new CreateInInfo(function_name->Value()[function_name->Length() - 1] == L'W', function_type));

        CComPtr<Breakpoints::DkmRuntimeInstructionBreakpoint> breakpoint;
        if(Breakpoints::DkmRuntimeInstructionBreakpoint::Create(source_id, nullptr, address, false, in_info, &breakpoint) != S_OK)
        {
            log_file_ << "  FAILED to create breakpoint!\n";
            log_file_.flush();
            continue;
        }

        if(breakpoint->Enable() != S_OK)
        {
            log_file_ << "  FAILED to enable breakpoint!\n";
            log_file_.flush();
            continue;
        }
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnRuntimeBreakpoint(
    Breakpoints::DkmRuntimeBreakpoint* runtime_breakpoint,
    DkmThread*                         thread,
    bool /*has_exception*/,
    DkmEventDescriptorS* /*event_descriptor*/)
{
    if(!enabled_) return S_OK;
    if(!settings_.attach_any) return S_OK;

    log_file_ << "OnRuntimeBreakpoint (Debugger PID " << GetCurrentProcessId() << ")\n";
    std::array<wchar_t, 64> guid_str = {L'\0'};
    StringFromGUID2(runtime_breakpoint->SourceId(), guid_str.data(), guid_str.size());
    log_file_ << "  Source ID:" << utf16_to_utf8(guid_str.data()) << "\n";
    log_file_.flush();

    CComPtr<CreateInInfo> in_info;
    runtime_breakpoint->GetDataItem(&in_info);
    if(in_info != nullptr)
    {
        // This is a breakpoint when entering a process creation function.
        // We will do the following things:
        //  - extract some information about the process being created from the arguments passed to the creation function.
        //  - determine whether we want to suspend the child process.
        //  - maybe, modify the passed arguments to force  suspended start.
        //  - create a new breakpoint that is triggered when the create process function is finished.

        log_file_ << "  In PID " << thread->Process()->LivePart()->Id << ": Start CreateProcess: W " << in_info->get_is_unicode() << " Func " << (int)in_info->get_function_type() << "\n";
        log_file_.flush();

        switch(in_info->get_function_type())
        {
        case CreateFunctionType::create_process:
            return handle_call_to_create_process<CreateProcessFunctionCallContext>(settings_, log_file_, *thread, in_info->get_is_unicode());
        case CreateFunctionType::create_process_as_user:
            return handle_call_to_create_process<CreateProcessAsUserFunctionCallContext>(settings_, log_file_, *thread, in_info->get_is_unicode());
        case CreateFunctionType::create_process_with_token:
            return handle_call_to_create_process<CreateProcessWithTokenFunctionCallContext>(settings_, log_file_, *thread, in_info->get_is_unicode());
        case CreateFunctionType::create_process_with_logon:
            return handle_call_to_create_process<CreateProcessWithLogonFunctionCallContext>(settings_, log_file_, *thread, in_info->get_is_unicode());
        default:
            log_file_ << "  Unsupported create function type: " << ((int)in_info->get_function_type()) << ".\n";
            log_file_.flush();
            return S_FALSE;
        }
    }

    CComPtr<CreateOutInfo> out_info;
    runtime_breakpoint->GetDataItem(&out_info);
    if(out_info != nullptr)
    {
        // This is a breakpoint when a process creation has been completed.
        // We will do the following things:
        //  - extract the process ID if of the created child process.
        //  - inform the debug client (VS Code) about the newly created process, so that it can attach to it.

        log_file_ << "  In PID " << thread->Process()->LivePart()->Id << ": Finish CreateProcess"
                  << "\n";
        log_file_.flush();

        runtime_breakpoint->Close(); // Remove this breakpoint. We will create a new one for the next call.

        // Retrieve the current register values, required to extract the function return value.
        CONTEXT      context;
        const UINT32 context_flags = CONTEXT_CONTROL | CONTEXT_INTEGER; // NOLINT(misc-redundant-expression)
        if(thread->GetContext(context_flags, &context, sizeof(CONTEXT)) != S_OK)
        {
            log_file_ << "  FAILED to retrieve thread context.\n";
            log_file_.flush();
            return S_FALSE;
        }

        // The RAX register holds the return value.
        log_file_ << "  CreateProcess returned " << get_return_value(context) << "\n";
        if(get_return_value(context) == 0)
        {
            // Nothing to attach to if the CreateProcess call failed.
            log_file_.flush();
            return S_OK;
        }

        // Read the process information structure from the stack. This should have been populated with information
        // about the newly created process.
        PROCESS_INFORMATION proc_info;
        if(thread->Process()->ReadMemory(out_info->get_process_information_address(), DkmReadMemoryFlags::None, &proc_info, sizeof(PROCESS_INFORMATION), nullptr) != S_OK)
        {
            log_file_ << "  FAILED to read process information!\n";
            log_file_.flush();
            return S_FALSE;
        }

        // Try to extract the application name of the created child process.
        std::wstring application_name;
        auto* const  process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, proc_info.dwProcessId);
        if(process_handle != nullptr)
        {
            std::array<WCHAR, MAX_PATH> buffer; // FIXME: handle paths longer than MAX_PATH

            const auto size = GetProcessImageFileNameW(process_handle, buffer.data(), buffer.size());
            if(size > 0)
            {
                application_name = std::filesystem::path(buffer.data()).filename().native();
            }
            CloseHandle(process_handle);
        }

        log_file_ << "  Child App Name " << utf16_to_utf8(application_name) << "\n";
        log_file_ << "  Child PID " << proc_info.dwProcessId << " TID " << proc_info.dwThreadId << "\n";
        log_file_ << "  Child P-HANDLE " << proc_info.hProcess << " T-HANDLE " << proc_info.hThread << "\n";
        log_file_.flush();

        // To make sure all this does not impose any unwanted effects, we suspend
        // the current parent process here, and only resume it when the debugger
        // has been attached successfully to the child process.
        if(settings_.suspend_parents)
        {
            UINT32 external_suspension_count;
            if(thread->Suspend(true, &external_suspension_count) != 0)
            {
                log_file_ << "  FAILED to suspend parent process.\n";
                log_file_.flush();
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
        CComPtr<DkmString> message_str;
        if(DkmString::Create((L"ChildDebugger: attach to child NAME '" + application_name +
                              L"' PPID " + std::to_wstring(thread->Process()->LivePart()->Id) +
                              L" PTID " + std::to_wstring(thread->SystemPart()->Id) +
                              L" CPID " + std::to_wstring(proc_info.dwProcessId) +
                              L" CTID " + std::to_wstring(proc_info.dwThreadId) +
                              (out_info->get_suspended() ? L" CSUSPENDED" : L"") +
                              (settings_.suspend_parents ? L" PSUSPENDED" : L"") + L"\n")
                                 .c_str(),
                             &message_str) != S_OK)
        {
            log_file_ << "  FAILED to create string for message!\n";
            log_file_.flush();
            return S_FALSE;
        }

        CComPtr<DkmUserMessage> message;
        if(DkmUserMessage::Create(thread->Connection(), thread->Process(), DkmUserMessageOutputKind::UnfilteredOutputWindowMessage, message_str, MB_OK, S_OK, &message) != S_OK)
        {
            log_file_ << "  FAILED to create user message!\n";
            log_file_.flush();
            return S_FALSE;
        }

        if(message->Post() != S_OK)
        {
            log_file_ << "  FAILED to post user message!\n";
            log_file_.flush();
            return S_FALSE;
        }

        return S_OK;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE CChildDebuggerService::OnEmbeddedBreakpointHitReceived(
    _In_ DkmThread*                 thread,
    _In_opt_ DkmInstructionAddress* instruction_address,
    _In_ bool /*show_as_exception*/,
    _In_ DkmEventDescriptorS* event_descriptor)
{
    if(!enabled_) return S_OK;
    if(!settings_.skip_initial_breakpoint) return S_OK;

    log_file_ << "On OnEmbeddedBreakpointHitReceived (Debugger PID " << GetCurrentProcessId() << ")\n";

    // The initial breakpoint is in ntdll.dll!LdrpDoDebuggerBreak()
    if(DkmString::CompareOrdinalIgnoreCase(instruction_address->ModuleInstance()->Name(), L"ntdll.dll") != 0) return S_OK;

    log_file_ << "  IN NTDLL\n";
    log_file_.flush();

    log_file_ << " THREAD " << thread << "\n";
    log_file_.flush();

    if(thread == nullptr) return S_FALSE;
    log_file_ << " PROCESS " << thread->Process() << "\n";
    log_file_.flush();
    if(thread->Process() == nullptr) return S_FALSE;

    log_file_ << "  Has process\n";
    log_file_.flush();

    CComPtr<ChildProcessDataItem> child_info;
    if(thread->Process()->GetDataItem(&child_info) != S_OK)
    {
        log_file_ << "  FAILED to get process child info.\n";
        log_file_.flush();
        return S_FALSE;
    }
    if(!child_info)
    {
        log_file_ << "  NO child info\n";
        log_file_.flush();
        return S_OK;
    }

    log_file_ << "  Has child info\n";
    log_file_ << "    Passed Initial Breakpoint " << child_info->get_passed_initial_breakpoint() << "\n";
    log_file_.flush();

    // Skip if we passed the initial breakpoint already
    if(child_info->get_passed_initial_breakpoint()) return S_OK;

    // This has to be the initial breakpoint, so suppress handling it.
    event_descriptor->Suppress();

    // Set, that we passed the initial breakpoint for this process.
    child_info->set_passed_initial_breakpoint();

    log_file_ << "  Suppressed\n";
    log_file_.flush();

    return S_OK;
}
