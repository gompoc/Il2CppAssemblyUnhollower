using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
#if USE_CAPSTONE
using System.Runtime.CompilerServices;
using Decoder = UnhollowerRuntimeLib.XrefScans.XrefScanner.DecoderSettings;
#else
using Iced.Intel;
#endif
using UnhollowerBaseLib;
using UnhollowerBaseLib.Attributes;
using Type = Il2CppSystem.Type;

namespace UnhollowerRuntimeLib.XrefScans
{
    public static class XrefScanner
    {
        public static unsafe IEnumerable<XrefInstance> XrefScan(MethodBase methodBase)
        {
            var fieldValue = UnhollowerUtils.GetIl2CppMethodInfoPointerFieldForGeneratedMethod(methodBase)?.GetValue(null);
            if (fieldValue == null) return Enumerable.Empty<XrefInstance>();
            
            var cachedAttribute = methodBase.GetCustomAttribute<CachedScanResultsAttribute>(false);
            if (cachedAttribute == null)
            {
                XrefScanMetadataRuntimeUtil.CallMetadataInitForMethod(methodBase);
                return XrefScanImpl(DecoderForAddress(*(IntPtr*)(IntPtr)fieldValue));
            }

            if (cachedAttribute.XrefRangeStart == cachedAttribute.XrefRangeEnd)
                return Enumerable.Empty<XrefInstance>();
            
            XrefScanMethodDb.CallMetadataInitForMethod(cachedAttribute);

            return XrefScanMethodDb.CachedXrefScan(cachedAttribute).Where(it => it.Type == XrefType.Method || XrefGlobalClassFilter(it.Pointer));
        }

        public static IEnumerable<XrefInstance> UsedBy(MethodBase methodBase)
        {
            var cachedAttribute = methodBase.GetCustomAttribute<CachedScanResultsAttribute>(false);
            if (cachedAttribute == null || cachedAttribute.RefRangeStart == cachedAttribute.RefRangeEnd)
                return Enumerable.Empty<XrefInstance>();

            return XrefScanMethodDb.ListUsers(cachedAttribute);
        }

#if USE_CAPSTONE
        internal static unsafe Decoder DecoderForAddress(IntPtr codeStart, int lengthLimit = 1000)
        {
            return new DecoderSettings
            { 
                codeStart = (ulong)codeStart,
                transaction = CSHelper.GetAsyncId(),
                limit = lengthLimit
            };
        }
#else
        internal static unsafe Decoder DecoderForAddress(IntPtr codeStart, int lengthLimit = 1000)
        {
            if (codeStart == IntPtr.Zero) throw new NullReferenceException(nameof(codeStart));

            var stream = new UnmanagedMemoryStream((byte*)codeStart, lengthLimit, lengthLimit, FileAccess.Read);
            var codeReader = new StreamCodeReader(stream);
            var decoder = Decoder.Create(IntPtr.Size * 8, codeReader);
            decoder.IP = (ulong)codeStart;

            return decoder;
        }
#endif

#if USE_CAPSTONE
        [StructLayout(LayoutKind.Sequential)]
        internal struct XrefScanImplNativeRes
        {
            public int type;
            public bool complete;
            public ulong target;
            public ulong codeStart;
        };

        [StructLayout(LayoutKind.Explicit)]
        internal struct DecoderSettings
        {
            [FieldOffset(0)]
            public ulong codeStart;
            [FieldOffset(8)]
            public ulong transaction;
            [FieldOffset(16)]
            public int limit;
        }

        internal static IEnumerable<XrefInstance> XrefScanImpl(Decoder decoder, bool skipClassCheck = false) {
            XrefScanImplNativeRes res;
            do
            {
                res = new XrefScanImplNativeRes();

                XrefScanImpl_Native(ref decoder, skipClassCheck, ref res);

                if (res.complete)
                {
                    break;
                }

                //LogSupport.Info($"{((XrefType)res.type).ToString()} {res.complete} {string.Format("0x{0:X8} 0x{0:X8}", res.target, res.codeStart)}");

                if(((XrefType)res.type) == XrefType.Global)
                {
                    if (skipClassCheck || XrefGlobalClassFilter((IntPtr)res.target))
                    {
                        var hit = new XrefInstance((XrefType)res.type, (IntPtr)res.target, (IntPtr)res.codeStart);
                        yield return hit;
                    }
                }
                else
                {
                    yield return new XrefInstance((XrefType)res.type, (IntPtr)res.target, (IntPtr)res.codeStart);
                }
                
            } while (!res.complete);
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        private extern static void XrefScanImpl_Native(ref Decoder decoder, bool skipClassCheck, ref XrefScanImplNativeRes nativeRes);
#else

        internal static IEnumerable<XrefInstance> XrefScanImpl(Decoder decoder, bool skipClassCheck = false)
        {
            while (true)
            {
                decoder.Decode(out var instruction);
                if (decoder.LastError == DecoderError.NoMoreBytes) yield break;

                if (instruction.FlowControl == FlowControl.Return)
                    yield break;

                if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                    yield break;

                if (instruction.Mnemonic == Mnemonic.Call || instruction.Mnemonic == Mnemonic.Jmp)
                {
                    var targetAddress = ExtractTargetAddress(instruction);
                    if (targetAddress != 0)
                        yield return new XrefInstance(XrefType.Method, (IntPtr) targetAddress, (IntPtr) instruction.IP);
                    continue;
                }
                
                if (instruction.FlowControl == FlowControl.UnconditionalBranch)
                    continue;

                if (instruction.Mnemonic == Mnemonic.Mov)
                {
                    XrefInstance? result = null;
                    try
                    {
                        if (instruction.Op1Kind == OpKind.Memory && instruction.IsIPRelativeMemoryOperand)
                        {
                            var movTarget = (IntPtr) instruction.IPRelativeMemoryAddress;
                            if (instruction.MemorySize != MemorySize.UInt64) 
                                continue;
                            
                            if (skipClassCheck || XrefGlobalClassFilter(movTarget))
                                result = new XrefInstance(XrefType.Global, movTarget, (IntPtr) instruction.IP);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogSupport.Error(ex.ToString());
                    }

                    if (result != null)
                        yield return result.Value;
                }
            }
        }
#endif

        internal static bool XrefGlobalClassFilter(IntPtr movTarget)
        {
            var valueAtMov = (IntPtr) Marshal.ReadInt64(movTarget);
            if (valueAtMov != IntPtr.Zero)
            {
                var targetClass = (IntPtr) Marshal.ReadInt64(valueAtMov);
                return targetClass == Il2CppClassPointerStore<string>.NativeClassPtr ||
                       targetClass == Il2CppClassPointerStore<Type>.NativeClassPtr;
            }

            return false;
        }
#if !USE_CAPSTONE
        internal static ulong ExtractTargetAddress(in Instruction instruction)
        {
            switch (instruction.Op0Kind)
            {
                case OpKind.NearBranch16:
                    return instruction.NearBranch16;
                case OpKind.NearBranch32:
                    return instruction.NearBranch32;
                case OpKind.NearBranch64:
                    return instruction.NearBranch64;
                case OpKind.FarBranch16:
                    return instruction.FarBranch16;
                case OpKind.FarBranch32:
                    return instruction.FarBranch32;
                default:
                    return 0;
            }
        }
#endif
    }
}
