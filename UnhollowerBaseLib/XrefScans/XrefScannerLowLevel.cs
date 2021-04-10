using System;
using System.Collections.Generic;
#if USE_CAPSTONE
using System.Runtime.CompilerServices;
using System.IO;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;
using UnhollowerBaseLib;
using Decoder = System.IntPtr;
#else
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;
#endif

namespace UnhollowerRuntimeLib.XrefScans
{
    public static class XrefScannerLowLevel
    {

#if USE_CAPSTONE
        public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart)
        {
            yield return JumpTargetsImpl(codeStart);
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        private extern static IntPtr JumpTargetsImpl(Decoder codeStart);

        //public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart)
        //{
        //    return JumpTargetsImpl(codeStart);
        //}
        //private static IEnumerable<IntPtr> JumpTargetsImpl(IntPtr codeStart)
        //{
        //    var stream = XrefScanner.DecoderForAddress(codeStart);
        //    const Arm64DisassembleMode disassembleMode = Arm64DisassembleMode.Arm;
        //    using (CapstoneArm64Disassembler disassembler = CapstoneDisassembler.CreateArm64Disassembler(disassembleMode))
        //    using (stream)
        //    {
        //        // ....
        //        //
        //        // Enables disassemble details, which are disabled by default, to provide more detailed information on
        //        // disassembled binary code.
        //        disassembler.EnableInstructionDetails = true;
        //        disassembler.DisassembleSyntax = DisassembleSyntax.Intel;


        //        var binaryCode = XrefScanner.ReadToEnd(stream);

        //        var instructions = disassembler.Iterate(binaryCode);
        //        foreach (Arm64Instruction instruction in instructions)
        //        {
        //            if (!instruction.HasDetails || instruction.IsDietModeEnabled)
        //                continue;

        //            if (XrefScanner.MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_RET))
        //                yield break;


        //            if (XrefScanner.MatchInstructionGroup(instruction, new[] { Arm64InstructionGroupId.ARM64_GRP_JUMP, Arm64InstructionGroupId.ARM64_GRP_CALL }))
        //            {
        //                yield return (IntPtr)ExtractTargetAddress(in instruction);
        //                if (XrefScanner.MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_JUMP)) yield break;
        //            }
        //        }
        //    }
        //}

        //private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(IntPtr codeStart)
        //{
        //    var stream = XrefScanner.DecoderForAddress(codeStart);
        //    const Arm64DisassembleMode disassembleMode = Arm64DisassembleMode.Arm;
        //    using (CapstoneArm64Disassembler disassembler = CapstoneDisassembler.CreateArm64Disassembler(disassembleMode))
        //    using (stream)
        //    {
        //        // ....
        //        //
        //        // Enables disassemble details, which are disabled by default, to provide more detailed information on
        //        // disassembled binary code.
        //        disassembler.EnableInstructionDetails = true;
        //        disassembler.DisassembleSyntax = DisassembleSyntax.Intel;


        //        var binaryCode = XrefScanner.ReadToEnd(stream);

        //        var instructions = disassembler.Iterate(binaryCode);
        //        foreach (Arm64Instruction instruction in instructions)
        //        {
        //            if (!instruction.HasDetails || instruction.IsDietModeEnabled)
        //                continue;

        //            if (XrefScanner.MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_RET))
        //                yield break;

        //            if (XrefScanner.MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_INT))
        //                yield break;

        //            // Unconditional Branch that return
        //            if (XrefScanner.MatchInstructionGroup(instruction, new[] { Arm64InstructionGroupId.ARM64_GRP_CALL, Arm64InstructionGroupId.ARM64_GRP_JUMP }))
        //            {
        //                LogSupport.Info($"{instruction.Details.Operands} operands");
        //                foreach (var operand in instruction.Details.Operands)
        //                {
        //                    LogSupport.Info(operand.Type.ToString());
        //                }
        //                continue;
        //            }

        //            if (
        //                instruction.Id >= Arm64InstructionId.ARM64_INS_LD1 || 
        //                instruction.Id <= Arm64InstructionId.ARM64_INS_LDXR || 
        //                instruction.Id >= Arm64InstructionId.ARM64_INS_ST1 || 
        //                instruction.Id <= Arm64InstructionId.ARM64_INS_STXRH
        //                )
        //            {
        //                if (instruction.Details.Operands[1].Type == Arm64OperandType.Memory)
        //                {
        //                    var memory = instruction.Details.Operands[1].Memory;
        //                    var isRelative = (memory.Base.Id >= Arm64RegisterId.ARM64_REG_X0 && memory.Base.Id <= Arm64RegisterId.ARM64_REG_X28);

        //                    if (isRelative)
        //                    {
        //                        var movTarget = (ulong)memory.Displacement | ((ulong)memory.Displacement << 32);
        //                        yield return (IntPtr)movTarget;
        //                    }
        //                }
        //            }
        //        }
        //    }
        //}

        //private static ulong ExtractTargetAddress(in Arm64Instruction instruction)
        //{
        //    return 0;
        //}
#else
        public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart)
        {
            return JumpTargetsImpl(codeStart);
        }

        private static IEnumerable<IntPtr> JumpTargetsImpl(Decoder myDecoder)
        {
            while (true)
            {
                myDecoder.Decode(out var instruction);
                if (myDecoder.LastError == DecoderError.NoMoreBytes) yield break;
                if (instruction.FlowControl == FlowControl.Return)
                    yield break;

                if (instruction.FlowControl == FlowControl.UnconditionalBranch || instruction.FlowControl == FlowControl.Call)
                {
                    yield return (IntPtr) ExtractTargetAddress(in instruction);
                    if(instruction.FlowControl == FlowControl.UnconditionalBranch) yield break;
                }
            }
        }

        public static IEnumerable<IntPtr> CallAndIndirectTargets(IntPtr pointer) => CallAndIndirectTargetsImpl(XrefScanner.DecoderForAddress(pointer, 1024 * 1024));

        private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(Decoder decoder)
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
                    var targetAddress = XrefScanner.ExtractTargetAddress(instruction);
                    if (targetAddress != 0)
                        yield return (IntPtr) targetAddress;
                    continue;
                }

                if (instruction.Mnemonic == Mnemonic.Lea)
                {
                    if (instruction.MemoryBase == Register.RIP)
                    {
                        var targetAddress = instruction.IPRelativeMemoryAddress;
                        if (targetAddress != 0)
                            yield return (IntPtr) targetAddress;
                    }
                }
            }
        }

        private static ulong ExtractTargetAddress(in Instruction instruction)
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
                    throw new ArgumentOutOfRangeException();
            }
        }
#endif
    }
}