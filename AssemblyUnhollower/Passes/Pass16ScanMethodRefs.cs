using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using AssemblyUnhollower.Contexts;
using AssemblyUnhollower.Extensions;
using UnhollowerRuntimeLib.XrefScans;

namespace AssemblyUnhollower.Passes
{
    public static class Pass16ScanMethodRefs
    {
        public static readonly HashSet<long> NonDeadMethods = new HashSet<long>();
        public static IDictionary<long, List<XrefInstance>> MapOfCallers = new Dictionary<long, List<XrefInstance>>();

        public static void DoPass(RewriteGlobalContext context, UnhollowerOptions options)
        {
            if (string.IsNullOrEmpty(options.GameAssemblyPath))
            {
                Pass15GenerateMemberContexts.HasObfuscatedMethods = false;
                return;
            }
            if (!Pass15GenerateMemberContexts.HasObfuscatedMethods) return;

            var methodToCallersMap = new ConcurrentDictionary<long, List<XrefInstance>>();
            var methodToCalleesMap = new ConcurrentDictionary<long, List<long>>();

            using var mappedFile = MemoryMappedFile.CreateFromFile(options.GameAssemblyPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using var accessor = mappedFile.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);

            IntPtr gameAssemblyPtr;

#if USE_CAPSTONE
            gameAssemblyPtr = CSHelper.GetAsmLoc();
#else
            unsafe
            {
                byte* fileStartPtr = null;
                accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref fileStartPtr);
                gameAssemblyPtr = (IntPtr) fileStartPtr;
            }
#endif
            var methods = context.Assemblies.SelectMany(it => it.Types).SelectMany(it => it.Methods);
            UnhollowerBaseLib.LogSupport.Error($"Scanning {methods.Count().ToString()} methods");
            int i = 0;
#if !USE_CAPSTONE
            // Scan xrefs
            methods.AsParallel().ForAll(
                originalTypeMethod =>
#else
            foreach (var originalTypeMethod in methods)
#endif
                {
                    
                    var address = originalTypeMethod.FileOffset;
                    //UnhollowerBaseLib.LogSupport.Info(address.ToString());
#if USE_CAPSTONE
                if (address == 0) continue;
#else
                if (address == 0) return;
#endif
                if (!options.NoXrefCache)
                    {
                        var pair = XrefScanMetadataGenerationUtil.FindMetadataInitForMethod(originalTypeMethod, (long) gameAssemblyPtr);
                        originalTypeMethod.MetadataInitFlagRva = pair.FlagRva;
                        originalTypeMethod.MetadataInitTokenRva = pair.TokenRva;
                        //UnhollowerBaseLib.LogSupport.Info("end");
                    }

                    foreach (var callTargetGlobal in XrefScanner.XrefScanImpl(XrefScanner.DecoderForAddress(IntPtr.Add(gameAssemblyPtr, (int) address), 0x1000), true))
                    {
                        var callTarget = callTargetGlobal.RelativeToBase((long) gameAssemblyPtr + originalTypeMethod.FileOffset - originalTypeMethod.Rva);
                        if (callTarget.Type == XrefType.Method)
                        {
                            var targetRelative = (long) callTarget.Pointer;
                            methodToCallersMap.GetOrAdd(targetRelative, _ => new List<XrefInstance>()).AddLocked(new XrefInstance(XrefType.Method, (IntPtr) originalTypeMethod.Rva, callTarget.FoundAt));
                            methodToCalleesMap.GetOrAdd(originalTypeMethod.Rva, _ => new List<long>()).AddLocked(targetRelative);
                        }

                        if (!options.NoXrefCache)
                            originalTypeMethod.XrefScanResults.Add(callTarget);
                    }
                    if (i %100 ==0 )
                UnhollowerBaseLib.LogSupport.Error($"Scanned {i + 1}/{methods.Count().ToString()} methods");
                i++;
            }

                
#if !USE_CAPSTONE
            );
#endif

            UnhollowerBaseLib.LogSupport.Info("pass complete");

            MapOfCallers = methodToCallersMap;

            void MarkMethodAlive(long address)
            {
                if (!NonDeadMethods.Add(address)) return;
                if (!methodToCalleesMap.TryGetValue(address, out var calleeList)) return;
                
                foreach (var callee in calleeList) 
                    MarkMethodAlive(callee);
            }
            
            // Now decided which of them are possible dead code
            foreach (var assemblyRewriteContext in context.Assemblies)
            foreach (var typeRewriteContext in assemblyRewriteContext.Types)
            foreach (var methodRewriteContext in typeRewriteContext.Methods)
            {
                if (methodRewriteContext.FileOffset == 0) continue;
                
                var originalMethod = methodRewriteContext.OriginalMethod;
                if (!originalMethod.Name.IsObfuscated(options) || originalMethod.IsVirtual)
                    MarkMethodAlive(methodRewriteContext.Rva);
            }
        }
    }
}