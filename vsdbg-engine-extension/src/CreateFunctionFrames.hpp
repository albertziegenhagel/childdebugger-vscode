#pragma once

#include <cstdint>

struct CreateProcessStack
{
#if defined(_X86_) || defined(_ARM_)
    using ptr_int_t = std::uint32_t;
#else
    using ptr_int_t = std::uint64_t;
#endif

    ptr_int_t return_address;

    ptr_int_t     lpApplicationName;   // NOLINT(readability-identifier-naming)
    ptr_int_t     lpCommandLine;       // NOLINT(readability-identifier-naming)
    ptr_int_t     lpProcessAttributes; // NOLINT(readability-identifier-naming)
    ptr_int_t     lpThreadAttributes;  // NOLINT(readability-identifier-naming)
    std::uint8_t  bInheritHandles;     // NOLINT(readability-identifier-naming)
    std::uint8_t  Padding1;            // NOLINT(readability-identifier-naming)
    std::uint16_t Padding2;            // NOLINT(readability-identifier-naming)
#if defined(_AMD64_) || defined(_ARM64_)
    std::uint32_t Padding3; // NOLINT(readability-identifier-naming)
#endif
    std::uint32_t dwCreationFlags; // NOLINT(readability-identifier-naming)
#if defined(_AMD64_) || defined(_ARM64_)
    // std::uint32_t       Padding4;             // NOLINT(readability-identifier-naming)
#endif
    ptr_int_t lpEnvironment;        // NOLINT(readability-identifier-naming)
    ptr_int_t lpCurrentDirectory;   // NOLINT(readability-identifier-naming)
    ptr_int_t lpStartupInfo;        // NOLINT(readability-identifier-naming)
    ptr_int_t lpProcessInformation; // NOLINT(readability-identifier-naming)

    // NOLINTNEXTLINE(readability-identifier-naming, readability-convert-member-functions-to-static)
    [[nodiscard]] ptr_int_t get_lpApplicationName([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_)
        return lpApplicationName;
#elif defined(_AMD64_)
        return context.Rcx;
#elif defined(_ARM_)
        return context.R9;
#elif defined(_ARM64_)
        return context.X9;
#endif
    }

    // NOLINTNEXTLINE(readability-identifier-naming, readability-convert-member-functions-to-static)
    [[nodiscard]] ptr_int_t get_lpCommandLine([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_)
        return lpCommandLine;
#elif defined(_AMD64_)
        return context.Rdx;
#elif defined(_ARM_)
        return context.R1;
#elif defined(_ARM64_)
        return context.X0;
#endif
    }

    // NOLINTNEXTLINE(readability-identifier-naming, readability-convert-member-functions-to-static)
    [[nodiscard]] DWORD64 get_lpProcessInformation([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_)
        return lpProcessInformation;
#elif defined(_AMD64_)
        return lpProcessInformation;
#elif defined(_ARM_)
        return context.R2;
#elif defined(_ARM64_)
        return context.X2;
#endif
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    [[nodiscard]] DWORD64 get_return_address([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_) || defined(_AMD64_)
        return return_address;
#elif defined(_ARM_)
        return context.Lr;
#elif defined(_ARM64_)
        return context.Lr;
#endif
    }
};

struct CreateProcessAsUserStack
{
#if defined(_X86_) || defined(_ARM_)
    using ptr_int_t = std::uint32_t;
#else
    using ptr_int_t = std::uint64_t;
#endif

    ptr_int_t return_address; // NOLINT(readability-identifier-naming)

    ptr_int_t hToken; // NOLINT(readability-identifier-naming)

    ptr_int_t     lpApplicationName;   // NOLINT(readability-identifier-naming)
    ptr_int_t     lpCommandLine;       // NOLINT(readability-identifier-naming)
    ptr_int_t     lpProcessAttributes; // NOLINT(readability-identifier-naming)
    ptr_int_t     lpThreadAttributes;  // NOLINT(readability-identifier-naming)
    std::uint8_t  bInheritHandles;     // NOLINT(readability-identifier-naming)
    std::uint8_t  Padding1;            // NOLINT(readability-identifier-naming)
    std::uint16_t Padding2;            // NOLINT(readability-identifier-naming)
#if defined(_AMD64_) || defined(_ARM64_)
    std::uint32_t Padding3; // NOLINT(readability-identifier-naming)
#endif
    std::uint32_t dwCreationFlags; // NOLINT(readability-identifier-naming)
#if defined(_AMD64_) || defined(_ARM64_)
    std::uint32_t Padding4; // NOLINT(readability-identifier-naming)
#endif
    ptr_int_t lpEnvironment;        // NOLINT(readability-identifier-naming)
    ptr_int_t lpCurrentDirectory;   // NOLINT(readability-identifier-naming)
    ptr_int_t lpStartupInfo;        // NOLINT(readability-identifier-naming)
    ptr_int_t lpProcessInformation; // NOLINT(readability-identifier-naming)

    // NOLINTNEXTLINE(readability-identifier-naming, readability-convert-member-functions-to-static)
    [[nodiscard]] DWORD64 get_lpApplicationName([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_)
        return lpApplicationName;
#elif defined(_AMD64_)
        return context.Rdx;
#elif defined(_ARM_)
        return context.R1;
#elif defined(_ARM64_)
        return context.X1;
#endif
    }

    // NOLINTNEXTLINE(readability-identifier-naming, readability-convert-member-functions-to-static)
    [[nodiscard]] DWORD64 get_lpCommandLine([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_)
        return lpCommandLine;
#elif defined(_AMD64_)
        return context.R8;
#elif defined(_ARM_)
        return context.R2;
#elif defined(_ARM64_)
        return context.X2;
#endif
    }

    // NOLINTNEXTLINE(readability-identifier-naming, readability-convert-member-functions-to-static)
    [[nodiscard]] DWORD64 get_lpProcessInformation([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_)
        return lpProcessInformation;
#elif defined(_AMD64_)
        return lpProcessInformation;
#elif defined(_ARM_)
        return lpProcessInformation;
#elif defined(_ARM64_)
        return lpProcessInformation;
#endif
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    [[nodiscard]] DWORD64 get_return_address([[maybe_unused]] const CONTEXT& context) const
    {
#if defined(_X86_) || defined(_AMD64_)
        return return_address;
#elif defined(_ARM_)
        return context.Lr;
#elif defined(_ARM64_)
        return context.Lr;
#endif
    }
};

[[nodiscard]] inline auto get_stack_pointer(const CONTEXT& context)
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
