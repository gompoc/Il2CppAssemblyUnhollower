using System.Linq;
using System.Threading.Tasks;
using AssemblyUnhollower.Contexts;
using UnhollowerBaseLib;

namespace AssemblyUnhollower.Passes
{
    public static class Pass90WriteToDisk
    {
        public static void DoPass(RewriteGlobalContext context, UnhollowerOptions options)
        {
            var tasks = context.Assemblies.Where(it =>
                !options.AdditionalAssembliesBlacklist.Contains(it.NewAssembly.Name.Name));
            
            foreach (var assemblyContext in tasks)
            {
                LogSupport.Info($"writing {options.OutputDir}/{assemblyContext.NewAssembly.Name.Name}.dll");
                assemblyContext.NewAssembly.Write(options.OutputDir + "/" + assemblyContext.NewAssembly.Name.Name + ".dll");
            }
        }
    }
}