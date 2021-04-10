using System;
#if USE_CAPSTONE
using System.Runtime.CompilerServices;
#else
using Iced.Intel;
#endif

namespace UnhollowerRuntimeLib.XrefScans
{
    internal static class XrefScanUtilFinder
    {
#if USE_CAPSTONE
        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern static IntPtr FindLastRcxReadAddressBeforeCallTo(IntPtr codeStart, IntPtr callTarget);
        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern static IntPtr FindByteWriteTargetRightAfterCallTo(IntPtr codeStart, IntPtr callTarget);

        //public static IntPtr FindLastRcxReadAddressBeforeCallTo(IntPtr codeStart, IntPtr callTarget)
        //{
        //    var stream = XrefScanner.DecoderForAddress(codeStart);
        //    IntPtr lastRcxRead = IntPtr.Zero;

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
        //                return IntPtr.Zero;

        //            if (XrefScanner.MatchInstructionGroup(instruction, Arm64InstructionGroupId.ARM64_GRP_RET))
        //                return IntPtr.Zero;

        //            if (XrefScanner.MatchInstructionGroup(instruction, new[] { Arm64InstructionGroupId.ARM64_GRP_JUMP }))
        //                continue;

        //            if (XrefScanner.MatchInstructionGroup(instruction, new[] { Arm64InstructionGroupId.ARM64_GRP_INT }))
        //                return IntPtr.Zero;

        //            if (XrefScanner.MatchInstructionGroup(instruction, new[] { Arm64InstructionGroupId.ARM64_GRP_CALL }))
        //            {
        //                IntPtr target = IntPtr.Zero;
        //                if ((IntPtr)target == callTarget)
        //                    return lastRcxRead;
        //            }

        //            if (instruction.Id == Arm64InstructionId.ARM64_INS_MOV)
        //            {
        //                if (
        //                    instruction.Details.Operands[0].Type == Arm64OperandType.Register && 
        //                    instruction.Details.Operands[0].Register.Id >= Arm64RegisterId.ARM64_REG_W0 && 
        //                    instruction.Details.Operands[0].Register.Id <= Arm64RegisterId.ARM64_REG_W30 && 
        //                    instruction.Details.Operands[1].Type == Arm64OperandType.Memory &&
        //                    instruction.Details.Operands[1].Memory.Base.Id >= Arm64RegisterId.ARM64_REG_W0 &&
        //                    instruction.Details.Operands[1].Memory.Base.Id <= Arm64RegisterId.ARM64_REG_W28
        //                    )
        //                {
        //                    lastRcxRead = (IntPtr)instruction.Details.Operands[1].Memory.Displacement;
        //                }
        //            }
        //        }
        //    }
        //}

        //public static IntPtr FindByteWriteTargetRightAfterCallTo(IntPtr codeStart, IntPtr callTarget)
        //{
        //    var decoder = XrefScanner.DecoderForAddress(codeStart);
        //    var seenCall = false;

        //    while (true)
        //    {
        //        decoder.Decode(out var instruction);
        //        if (decoder.LastError == DecoderError.NoMoreBytes) return IntPtr.Zero;

        //        if (instruction.FlowControl == FlowControl.Return)
        //            return IntPtr.Zero;

        //        if (instruction.FlowControl == FlowControl.UnconditionalBranch)
        //            continue;

        //        if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
        //            return IntPtr.Zero;

        //        if (instruction.Mnemonic == Mnemonic.Call)
        //        {
        //            var target = ExtractTargetAddress(instruction);
        //            if ((IntPtr)target == callTarget)
        //                seenCall = true;
        //        }

        //        if (instruction.Mnemonic == Mnemonic.Mov && seenCall)
        //        {
        //            if (instruction.Op0Kind == OpKind.Memory && (instruction.MemorySize == MemorySize.Int8 || instruction.MemorySize == MemorySize.UInt8))
        //                return (IntPtr)instruction.IPRelativeMemoryAddress;
        //        }
        //    }
        //}
#else
        public static IntPtr FindLastRcxReadAddressBeforeCallTo(IntPtr codeStart, IntPtr callTarget)
        {
            var decoder = XrefScanner.DecoderForAddress(codeStart);
            IntPtr lastRcxRead = IntPtr.Zero;
            
            while (true)
            {
                decoder.Decode(out var instruction);
                if (decoder.LastError == DecoderError.NoMoreBytes) return IntPtr.Zero;

                if (instruction.FlowControl == FlowControl.Return)
                    return IntPtr.Zero;

                if (instruction.FlowControl == FlowControl.UnconditionalBranch)
                    continue;

                if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                    return IntPtr.Zero;

                if (instruction.Mnemonic == Mnemonic.Call)
                {
                    var target = ExtractTargetAddress(instruction);
                    if ((IntPtr) target == callTarget)
                        return lastRcxRead;
                }

                if (instruction.Mnemonic == Mnemonic.Mov)
                {
                    if (instruction.Op0Kind == OpKind.Register && instruction.Op0Register == Register.ECX && instruction.Op1Kind == OpKind.Memory && instruction.IsIPRelativeMemoryOperand)
                    {
                        var movTarget = (IntPtr) instruction.IPRelativeMemoryAddress;
                        if (instruction.MemorySize != MemorySize.UInt32 && instruction.MemorySize != MemorySize.Int32) 
                            continue;
                        
                        lastRcxRead = movTarget;
                    }
                }
            }
        }
        
        public static IntPtr FindByteWriteTargetRightAfterCallTo(IntPtr codeStart, IntPtr callTarget)
        {
            var decoder = XrefScanner.DecoderForAddress(codeStart);
            var seenCall = false;
            
            while (true)
            {
                decoder.Decode(out var instruction);
                if (decoder.LastError == DecoderError.NoMoreBytes) return IntPtr.Zero;

                if (instruction.FlowControl == FlowControl.Return)
                    return IntPtr.Zero;

                if (instruction.FlowControl == FlowControl.UnconditionalBranch)
                    continue;

                if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                    return IntPtr.Zero;

                if (instruction.Mnemonic == Mnemonic.Call)
                {
                    var target = ExtractTargetAddress(instruction);
                    if ((IntPtr) target == callTarget)
                        seenCall = true;
                }

                if (instruction.Mnemonic == Mnemonic.Mov && seenCall)
                {
                    if (instruction.Op0Kind == OpKind.Memory && (instruction.MemorySize == MemorySize.Int8 || instruction.MemorySize == MemorySize.UInt8))
                        return (IntPtr) instruction.IPRelativeMemoryAddress;
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
                    return 0;
            }
        }
#endif
    }
}