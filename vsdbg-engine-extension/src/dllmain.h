#include <atlbase.h>

class CChildDebuggerModule : public CAtlDllModuleT<CChildDebuggerModule>
{
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, bugprone-reserved-identifier, readability-identifier-naming)
extern class CChildDebuggerModule _AtlModule;
