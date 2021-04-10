using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
#if USE_CAPSTONE
using System.Collections;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;
using Decoder = Gee.External.Capstone.Arm64.CapstoneArm64Disassembler;
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
                return XrefScanImpl(DecoderForAddress(*(IntPtr*)(IntPtr)fieldValue), *(IntPtr*)(IntPtr)fieldValue);
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
        internal static unsafe Stream DecoderForAddress(IntPtr codeStart, int lengthLimit = 1000)
        {
            if (codeStart == IntPtr.Zero) throw new NullReferenceException(nameof(codeStart));
            return new UnmanagedMemoryStream((byte*)codeStart, lengthLimit, lengthLimit, FileAccess.Read);
        }
#else
        internal static unsafe Decoder DecoderForAddress(IntPtr codeStart, int lengthLimit = 1000)
        {
            if (codeStart == IntPtr.Zero) throw new NullReferenceException(nameof(codeStart));

            var stream = new UnmanagedMemoryStream((byte*)codeStart, lengthLimit, lengthLimit, FileAccess.Read);
            var decoder = Decoder.Create(IntPtr.Size * 8, codeReader);
            decoder.IP = (ulong) codeStart;

            return decoder.Iterate(m_Bytes, codeStart.ToInt64());
        }
#endif

#if USE_CAPSTONE
        internal static byte[] ReadToEnd(System.IO.Stream stream)
        {
            long originalPosition = 0;

            if (stream.CanSeek)
            {
                originalPosition = stream.Position;
                stream.Position = 0;
            }

            try
            {
                byte[] readBuffer = new byte[4096];

                int totalBytesRead = 0;
                int bytesRead;

                while ((bytesRead = stream.Read(readBuffer, totalBytesRead, readBuffer.Length - totalBytesRead)) > 0)
                {
                    totalBytesRead += bytesRead;

                    if (totalBytesRead == readBuffer.Length)
                    {
                        int nextByte = stream.ReadByte();
                        if (nextByte != -1)
                        {
                            byte[] temp = new byte[readBuffer.Length * 2];
                            Buffer.BlockCopy(readBuffer, 0, temp, 0, readBuffer.Length);
                            Buffer.SetByte(temp, totalBytesRead, (byte)nextByte);
                            readBuffer = temp;
                            totalBytesRead++;
                        }
                    }
                }

                byte[] buffer = readBuffer;
                if (readBuffer.Length != totalBytesRead)
                {
                    buffer = new byte[totalBytesRead];
                    Buffer.BlockCopy(readBuffer, 0, buffer, 0, totalBytesRead);
                }
                return buffer;
            }
            finally
            {
                if (stream.CanSeek)
                {
                    stream.Position = originalPosition;
                }
            }
        }

        internal static IEnumerable<XrefInstance> XrefScanImpl(System.IO.Stream stream, IntPtr start, bool skipClassCheck = false, int lengthLimit = 1000)
        {
            const Arm64DisassembleMode disassembleMode = Arm64DisassembleMode.Arm;
            using (CapstoneArm64Disassembler disassembler = CapstoneDisassembler.CreateArm64Disassembler(disassembleMode))
            using (stream)
            {
                // ....
                //
                // Enables disassemble details, which are disabled by default, to provide more detailed information on
                // disassembled binary code.
                disassembler.EnableInstructionDetails = true;
                disassembler.DisassembleSyntax = DisassembleSyntax.Intel;
                

                var binaryCode = ReadToEnd(stream);

                var instructions = disassembler.Iterate(binaryCode);
                foreach (Arm64Instruction instruction in instructions)
                {
                    if (!instruction.HasDetails || instruction.IsDietModeEnabled)
                        continue;
                    
                    if (MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_RET))
                        yield break;


                    if (MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_INT))
                        yield break;

                    // Unconditional Branch that return
                    if (MatchInstructionGroup(instruction, new[] { Arm64InstructionGroupId.ARM64_GRP_CALL, Arm64InstructionGroupId.ARM64_GRP_JUMP }))
                    {
                        LogSupport.Info($"{instruction.Details.Operands} operands");
                        foreach (var operand in instruction.Details.Operands)
                        {
                            LogSupport.Info(operand.Type.ToString());
                        }
                        //if (instruction.Details.Operands)
                        //if (targetAddress != 0)
                        //    yield return new XrefInstance(XrefType.Method, (IntPtr)targetAddress, start);
                        continue;
                    }

                    // Unconditional Branch
                    if (new[] { 
                        Arm64InstructionId.ARM64_INS_B,
                        Arm64InstructionId.ARM64_INS_BL,
                        Arm64InstructionId.ARM64_INS_BR,
                        Arm64InstructionId.ARM64_INS_BLR,
                        Arm64InstructionId.ARM64_INS_RET,
                        Arm64InstructionId.ARM64_INS_ERET,
                        Arm64InstructionId.ARM64_INS_DRPS
                    }.Contains(instruction.Id))
                        continue;

                    if (instruction.Id == Arm64InstructionId.ARM64_INS_MOV)
                    {
                        if (instruction.Details.Operands[1].Type == Arm64OperandType.Memory)
                        {
                            var memory = instruction.Details.Operands[1].Memory;
                            var isRelative = (memory.Base.Id >= Arm64RegisterId.ARM64_REG_X0 || memory.Base.Id <= Arm64RegisterId.ARM64_REG_X28);

                            if (isRelative)
                            {
                                var movTarget = (ulong)memory.Displacement | ((ulong)memory.Displacement << 32);

                                if (skipClassCheck || XrefGlobalClassFilter((IntPtr)movTarget))
                                    yield return new XrefInstance(XrefType.Global, (IntPtr)movTarget, start);
                            }
                        }
                    }
                }
            }
        }
        #region MatchInstructionGroup
        internal static bool MatchInstructionGroup(Arm64Instruction instruction, Arm64InstructionGroupId groupId)
        {
            return MatchInstructionGroup(instruction.Details.Groups, groupId);
        }

        internal static bool MatchInstructionGroup(Arm64Instruction instruction, IEnumerable<Arm64InstructionGroupId> groupId)
        {
            return MatchInstructionGroup(instruction.Details.Groups, groupId);
        }

        internal static bool MatchInstructionGroup(IEnumerable<Arm64InstructionGroup> groups, Arm64InstructionGroupId groupId)
        {
            return groups.Any((g) => { return g.Id == Arm64InstructionGroupId.ARM64_GRP_RET; });
        }

        internal static bool MatchInstructionGroup(IEnumerable<Arm64InstructionGroup> groups, IEnumerable<Arm64InstructionGroupId> groupId)
        {
            return groups.Any((g) => { return groupId.Contains(g.Id); });
        }
        #endregion
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
#if USE_CAPSTONE
        internal static ulong ExtractTargetAddress(in Arm64Instruction instruction)
        {
            return 0;
        }
#else
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