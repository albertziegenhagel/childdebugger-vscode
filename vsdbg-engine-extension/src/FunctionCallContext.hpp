#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <tuple>
#include <utility>

template<typename ReturnValueType, typename... Args>
struct FunctionSignature
{
    static constexpr auto num_args = sizeof...(Args);
};

[[nodiscard]] inline std::uintptr_t get_stack_pointer(const CONTEXT& context)
{
#if defined(_X86_)
    return context.Esp;
#elif defined(_AMD64_)
    return context.Rsp;
#elif defined(_ARM_)
    return context.Sp;
#elif defined(_ARM64_)
    return context.Sp;
#endif
}

template<typename ReturnValueType, typename... Args>
[[nodiscard]] constexpr std::size_t get_stack_frame_size()
{
    // Assumes all arguments and the return value can be
    // passed in registers.
    static_assert((std::is_integral_v<Args> && ...));
    static_assert(((sizeof(Args) <= sizeof(void*)) && ...));

    static_assert(std::is_integral_v<ReturnValueType>);
    static_assert(sizeof(ReturnValueType) <= sizeof(void*));

    constexpr auto num_args = sizeof...(Args);

#if defined(_X86_) || defined(_AMD64_)
    // top of the stack frame always holds the return address.
    // Remaining arguments are aligned to the native word size.
    return (1 + num_args) * sizeof(void*);
#elif defined(_ARM_)
    // ARM does not store the return address on the stack and
    // does not reserve space for arguments passed in registers.
    return (num_args > 4 ? (num_args - 4) : 0) * sizeof(void*);
#elif defined(_ARM64_)
    return (num_args > 8 ? (num_args - 8) : 0) * sizeof(void*);
#endif
}

template<typename ReturnValueType, typename... Args>
[[nodiscard]] constexpr std::size_t get_stack_frame_size(const FunctionSignature<ReturnValueType, Args...>& /*unused*/)
{
    return get_stack_frame_size<ReturnValueType, Args...>();
}

template<typename FunctionSig>
struct StackFrameType;

template<typename ReturnValueType, typename... Args>
struct StackFrameType<FunctionSignature<ReturnValueType, Args...>>
{
    using type = std::array<std::byte, get_stack_frame_size<ReturnValueType, Args...>()>; // NOLINT(readability-identifier-naming)
};

template<typename FunctionSig>
using stack_frame_t = typename StackFrameType<FunctionSig>::type; // NOLINT(readability-identifier-naming)

template<std::size_t I, typename ContextType>
[[nodiscard]] auto& get_integral_argument_register_value(ContextType& context)
{
    static_assert(std::is_same_v<std::decay_t<ContextType>, CONTEXT>);

#if defined(_X86_)
    static_assert(false); // does not pass any arguments in registers
#elif defined(_AMD64_)
    static_assert(I < 4);
    switch(I)
    {
    case 0: return context.Rcx;
    case 1: return context.Rdx;
    case 2: return context.R8;
    case 3: return context.R9;
    }
#elif defined(_ARM_)
    static_assert(I < 4);
    switch(I)
    {
    case 0: return context.R0;
    case 1: return context.R1;
    case 2: return context.R2;
    case 3: return context.R3;
    }
#elif defined(_ARM64_)
    static_assert(I < 8);
    switch(I)
    {
    case 0: return context.X0;
    case 1: return context.X1;
    case 2: return context.X2;
    case 3: return context.X3;
    case 4: return context.X4;
    case 5: return context.X5;
    case 6: return context.X6;
    case 7: return context.X7;
    }
#endif
    std::unreachable();
}

template<typename T, std::size_t I>
[[nodiscard]] T get_integral_argument_register_value_as(const CONTEXT& context)
{
    static_assert(sizeof(T) <= sizeof(void*));
    static_assert(std::is_integral_v<T>);

    const auto register_value = get_integral_argument_register_value<I>(context);
    return std::bit_cast<T>(static_cast<std::make_unsigned_t<T>>(register_value));
}

template<std::size_t I, typename T>
void set_integral_argument_register_value(CONTEXT& context,
                                          const T& value)
{
    using ValueType = std::decay_t<T>;
    static_assert(std::is_integral_v<ValueType>);

    auto& register_value = get_integral_argument_register_value<I>(context);

    using RegisterType = std::decay_t<decltype(register_value)>;

    static_assert(sizeof(ValueType) <= sizeof(RegisterType));

    const auto value_in_register_type = static_cast<RegisterType>(value);

    constexpr auto value_type_mask = static_cast<RegisterType>(~std::make_unsigned_t<ValueType>(0));

    register_value = (register_value & ~value_type_mask) | (value_in_register_type & value_type_mask);
}

template<typename T, std::size_t Offset, std::size_t StackSize>
[[nodiscard]] T get_stack_value_as(const std::array<std::byte, StackSize>& stack_frame)
{
    static_assert(sizeof(T) <= sizeof(void*));
    static_assert(std::is_integral_v<T> || std::is_floating_point_v<T>);

    static_assert(Offset + sizeof(T) <= StackSize);

    return *reinterpret_cast<const T*>(stack_frame.data() + Offset);
}

template<std::size_t Offset, std::size_t StackSize, typename T>
void set_stack_value(std::array<std::byte, StackSize>& stack_frame,
                     const T&                          value)
{
    static_assert(sizeof(T) <= sizeof(void*));
    static_assert(std::is_integral_v<T> || std::is_floating_point_v<T>);

    static_assert(Offset + sizeof(T) <= StackSize);

    *reinterpret_cast<T*>(stack_frame.data() + Offset) = value;
}

template<std::size_t I, typename ReturnValueType, typename... Args>
[[nodiscard]] auto get_argument_value(const FunctionSignature<ReturnValueType, Args...>& /*unused*/,
                                      const std::array<std::byte, get_stack_frame_size<ReturnValueType, Args...>()>& stack_frame,
                                      const CONTEXT&                                                                 context)
{
    static_assert(I < sizeof...(Args));

    // Currently assumes that all arguments are of integral type and
    // are smaller than the native pointer size.
    // This significantly simplifies the logic what is passed in registers.
    static_assert((std::is_integral_v<Args> && ...));
    static_assert(((sizeof(Args) <= sizeof(void*)) && ...));

#if defined(_X86_)
    constexpr std::size_t num_register_args = 0;
#elif defined(_AMD64_)
    constexpr std::size_t num_register_args = 4;
#elif defined(_ARM_)
    constexpr std::size_t num_register_args = 4;
#elif defined(_ARM64_)
    constexpr std::size_t num_register_args = 8;
#endif

    using ArgType = std::tuple_element_t<I, std::tuple<Args...>>;

    if constexpr(I < num_register_args)
    {
        return get_integral_argument_register_value_as<ArgType, I>(context);
    }
    else
    {
#if defined(_X86_)
        constexpr auto offset = (1 + I) * sizeof(void*);
#elif defined(_AMD64_)
        constexpr auto offset = (1 + I) * sizeof(void*);
#elif defined(_ARM_)
        constexpr auto offset = (I - 4) * sizeof(void*);
#elif defined(_ARM64_)
        constexpr auto offset = (I - 8) * sizeof(void*);
#endif

        return get_stack_value_as<ArgType, offset>(stack_frame);
    }
}

template<std::size_t I, typename ReturnValueType, typename... Args>
void set_argument_value(const FunctionSignature<ReturnValueType, Args...>& /*unused*/,
                        std::array<std::byte, get_stack_frame_size<ReturnValueType, Args...>()>& stack_frame,
                        CONTEXT&                                                                 context,
                        const std::tuple_element_t<I, std::tuple<Args...>>&                      value,
                        bool&                                                                    stack_changed,
                        bool&                                                                    registers_changed)
{
    static_assert(I < sizeof...(Args));

    // Currently assumes that all arguments are of integral type and
    // are smaller than the native pointer size.
    // This significantly simplifies the logic what is passed in registers.
    static_assert((std::is_integral_v<Args> && ...));
    static_assert(((sizeof(Args) <= sizeof(void*)) && ...));

#if defined(_X86_)
    constexpr std::size_t num_register_args = 0;
#elif defined(_AMD64_)
    constexpr std::size_t num_register_args = 4;
#elif defined(_ARM_)
    constexpr std::size_t num_register_args = 4;
#elif defined(_ARM64_)
    constexpr std::size_t num_register_args = 8;
#endif

    if constexpr(I < num_register_args)
    {
        set_integral_argument_register_value<I>(context, value);
        registers_changed = true;
    }
    else
    {
#if defined(_X86_)
        constexpr auto offset = (1 + I) * sizeof(void*);
#elif defined(_AMD64_)
        constexpr auto offset = (1 + I) * sizeof(void*);
#elif defined(_ARM_)
        constexpr auto offset = (I - 4) * sizeof(void*);
#elif defined(_ARM64_)
        constexpr auto offset = (I - 8) * sizeof(void*);
#endif

        set_stack_value<offset>(stack_frame, value);
        stack_changed = true;
    }
}

[[nodiscard]] inline auto get_return_value(const CONTEXT& context)
{
#if defined(_X86_)
    return context.Eax;
#elif defined(_AMD64_)
    return context.Rax;
#elif defined(_ARM_)
    return context.R0;
#elif defined(_ARM64_)
    return context.X0;
#endif
}

template<std::size_t StackSize>
[[nodiscard]] std::uintptr_t get_return_address([[maybe_unused]] const std::array<std::byte, StackSize>& stack_frame,
                                                [[maybe_unused]] const CONTEXT&                          context)
{
#if defined(_X86_) || defined(_AMD64_)
    static_assert(StackSize >= sizeof(void*));
    return get_stack_value_as<std::uintptr_t, 0>(stack_frame);
#elif defined(_ARM_)
    return context.Lr;
#elif defined(_ARM64_)
    return context.Lr;
#endif
}

template<typename Signature>
struct BasicFunctionCallContext
{
    Signature                signature;
    CONTEXT                  registers;
    stack_frame_t<Signature> stack;

    bool registers_changed = false;
    bool stack_changed     = false;

    [[nodiscard]] auto get_return_address() const
    {
        return ::get_return_address(stack, registers);
    }
};

template<typename Signature,
         std::size_t lpApplicationNameIndex,
         std::size_t lpCommandLineIndex,
         std::size_t dwCreationFlagsIndex,
         std::size_t lpProcessInformationIndex>
struct ProcessCreationFunctionCallContext : public BasicFunctionCallContext<Signature>
{
    // NOLINTNEXTLINE(readability-identifier-naming)
    [[nodiscard]] auto get_lpApplicationName() const
    {
        return get_argument_value<lpApplicationNameIndex>(this->signature, this->stack, this->registers);
    }

    // NOLINTNEXTLINE(readability-identifier-naming)
    [[nodiscard]] auto get_lpCommandLine() const
    {
        return get_argument_value<lpCommandLineIndex>(this->signature, this->stack, this->registers);
    }

    // NOLINTNEXTLINE(readability-identifier-naming)
    [[nodiscard]] auto get_dwCreationFlags() const
    {
        return get_argument_value<dwCreationFlagsIndex>(this->signature, this->stack, this->registers);
    }

    template<typename T>
    // NOLINTNEXTLINE(readability-identifier-naming)
    void set_dwCreationFlags(const T& value)
    {
        set_argument_value<dwCreationFlagsIndex>(this->signature, this->stack, this->registers, value, this->stack_changed, this->registers_changed);
    }

    // NOLINTNEXTLINE(readability-identifier-naming)
    [[nodiscard]] auto get_lpProcessInformation() const
    {
        return get_argument_value<lpProcessInformationIndex>(this->signature, this->stack, this->registers);
    }
};

using CreateProcessFunctionCallContext = ProcessCreationFunctionCallContext<
    FunctionSignature</*BOOL*/ int,
                      std::uintptr_t,          // lpApplicationName,
                      std::uintptr_t,          // lpCommandLine,
                      std::uintptr_t,          // lpProcessAttributes,
                      std::uintptr_t,          // lpThreadAttributes,
                      /*BOOL*/ int,            // bInheritHandles,
                      /*DWORD*/ unsigned long, // dwCreationFlags,
                      std::uintptr_t,          // lpEnvironment,
                      std::uintptr_t,          // lpCurrentDirectory,
                      std::uintptr_t,          // lpStartupInfo,
                      std::uintptr_t           // lpProcessInformation
                      >,
    0, 1, 5, 9>;

using CreateProcessAsUserFunctionCallContext = ProcessCreationFunctionCallContext<
    FunctionSignature</*BOOL*/ int,
                      std::uintptr_t,          // hToken,
                      std::uintptr_t,          // lpApplicationName,
                      std::uintptr_t,          // lpCommandLine,
                      std::uintptr_t,          // lpProcessAttributes,
                      std::uintptr_t,          // lpThreadAttributes,
                      /*BOOL*/ int,            // bInheritHandles,
                      /*DWORD*/ unsigned long, // dwCreationFlags,
                      std::uintptr_t,          // lpEnvironment,
                      std::uintptr_t,          // lpCurrentDirectory,
                      std::uintptr_t,          // lpStartupInfo,
                      std::uintptr_t           // lpProcessInformation
                      >,
    1, 2, 6, 10>;
