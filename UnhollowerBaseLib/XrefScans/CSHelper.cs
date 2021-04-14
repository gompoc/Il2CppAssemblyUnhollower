#if USE_CAPSTONE
using System;
using System.Runtime.CompilerServices;

namespace UnhollowerRuntimeLib.XrefScans
{
    class CSHelper
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        static internal extern IntPtr GetAsmLoc();

        static internal void CleanupDisasm()
        {
            CleanupDisasm_Native();
            _idCounter = 0;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        static private extern void CleanupDisasm_Native();


        static private UInt64 _idCounter = 0;
        static internal UInt64 GetAsyncId()
        {
            return _idCounter++;
        }
    }
}
#endif