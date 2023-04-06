#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include <vsdebugeng.h>
#include <vsdebugeng.templates.h>

#include "dllmain.h"
#include "ntsuspend.h"

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
