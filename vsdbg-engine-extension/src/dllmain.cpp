#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include "dllmain.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
CChildDebuggerModule _AtlModule;

extern "C" BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    return _AtlModule.DllMain(dwReason, lpReserved);
}

STDAPI DllCanUnloadNow(void)
{
    return _AtlModule.DllCanUnloadNow();
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}
