#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include "dllmain.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
CChildDebuggerModule _AtlModule;

// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    return _AtlModule.DllMain(reason, reserved);
}

STDAPI DllCanUnloadNow(void)
{
    return _AtlModule.DllCanUnloadNow();
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}
