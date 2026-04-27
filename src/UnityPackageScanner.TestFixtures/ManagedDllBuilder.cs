using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;

namespace UnityPackageScanner.TestFixtures;

/// <summary>
/// Builds minimal managed .NET assemblies with specific metadata for testing detection rules.
/// Each method returns a byte array (MZ-magic, CLR directory present) written via a temp file.
/// </summary>
public static class ManagedDllBuilder
{
    /// <summary>Creates a managed DLL that calls <c>new System.Net.Http.HttpClient()</c>.</summary>
    public static byte[] WithNetworkAccess(string moduleName = "TestNetwork.dll") =>
        Build(moduleName, (module, type) =>
        {
            var asmRef = AddAssemblyRef(module, "System.Net.Http");
            var typeRef = new TypeReference(module, asmRef, "System.Net.Http", "HttpClient");
            AddCallMethod(module, type, "NetworkCall",
            [
                new CilInstruction(CilOpCodes.Newobj,
                    new MemberReference(typeRef, ".ctor", MethodSignature.CreateInstance(module.CorLibTypeFactory.Void))),
                new CilInstruction(CilOpCodes.Pop),
            ]);
        });

    /// <summary>Creates a managed DLL that calls <c>System.Diagnostics.Process.GetCurrentProcess()</c>.</summary>
    public static byte[] WithProcessSpawn(string moduleName = "TestProcess.dll") =>
        Build(moduleName, (module, type) =>
        {
            var asmRef = AddAssemblyRef(module, "System.Diagnostics.Process");
            var typeRef = new TypeReference(module, asmRef, "System.Diagnostics", "Process");
            AddCallMethod(module, type, "SpawnProcess",
            [
                new CilInstruction(CilOpCodes.Call,
                    new MemberReference(typeRef, "GetCurrentProcess",
                        MethodSignature.CreateStatic(module.CorLibTypeFactory.Object))),
                new CilInstruction(CilOpCodes.Pop),
            ]);
        });

    /// <summary>Creates a managed DLL that calls <c>System.Reflection.Assembly.LoadFrom(string)</c>.</summary>
    public static byte[] WithReflectionLoad(string moduleName = "TestReflection.dll") =>
        Build(moduleName, (module, type) =>
        {
            var asmRef = AddAssemblyRef(module, "System.Runtime");
            var typeRef = new TypeReference(module, asmRef, "System.Reflection", "Assembly");
            AddCallMethod(module, type, "LoadPlugin",
            [
                new CilInstruction(CilOpCodes.Ldnull),
                new CilInstruction(CilOpCodes.Call,
                    new MemberReference(typeRef, "LoadFrom",
                        MethodSignature.CreateStatic(module.CorLibTypeFactory.Object, module.CorLibTypeFactory.String))),
                new CilInstruction(CilOpCodes.Pop),
            ]);
        });

    /// <summary>Creates a managed DLL with a P/Invoke (<c>[DllImport]</c>) method declaration.</summary>
    public static byte[] WithPInvoke(string nativeDll = "kernel32.dll", string moduleName = "TestPInvoke.dll") =>
        Build(moduleName, (module, type) =>
        {
            var modRef = new ModuleReference(nativeDll);
            module.ModuleReferences.Add(modRef);

            var method = new MethodDefinition("VirtualAlloc",
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
                MethodSignature.CreateStatic(
                    module.CorLibTypeFactory.IntPtr,
                    module.CorLibTypeFactory.IntPtr,
                    module.CorLibTypeFactory.UIntPtr,
                    module.CorLibTypeFactory.UInt32,
                    module.CorLibTypeFactory.UInt32));

            method.ImplementationMap = new ImplementationMap(modRef, "VirtualAlloc",
                ImplementationMapAttributes.CallConvWinapi);
            type.Methods.Add(method);
        });

    /// <summary>Creates a managed DLL whose class carries a <c>[UnityEditor.InitializeOnLoad]</c> custom attribute.</summary>
    public static byte[] WithInitializeOnLoad(string moduleName = "TestInitOnLoad.dll") =>
        Build(moduleName, (module, type) =>
        {
            var unityEditor = AddAssemblyRef(module, "UnityEditor");
            var attrRef = new TypeReference(module, unityEditor, "UnityEditor", "InitializeOnLoadAttribute");
            type.CustomAttributes.Add(new CustomAttribute(
                new MemberReference(attrRef, ".ctor", MethodSignature.CreateInstance(module.CorLibTypeFactory.Void))));
        });

    /// <summary>Creates a managed DLL that calls <c>System.Runtime.InteropServices.NativeLibrary.Load(string)</c>.</summary>
    public static byte[] WithNativeLibraryLoad(string moduleName = "TestNativeLibrary.dll") =>
        Build(moduleName, (module, type) =>
        {
            var asmRef = AddAssemblyRef(module, "System.Runtime.InteropServices");
            var typeRef = new TypeReference(module, asmRef, "System.Runtime.InteropServices", "NativeLibrary");
            AddCallMethod(module, type, "LoadNative",
            [
                new CilInstruction(CilOpCodes.Ldnull),
                new CilInstruction(CilOpCodes.Call,
                    new MemberReference(typeRef, "Load",
                        MethodSignature.CreateStatic(module.CorLibTypeFactory.IntPtr, module.CorLibTypeFactory.String))),
                new CilInstruction(CilOpCodes.Pop),
            ]);
        });

    /// <summary>Creates a managed DLL with a class that inherits <c>UnityEditor.AssetPostprocessor</c>.</summary>
    public static byte[] WithAssetPostprocessor(string moduleName = "TestPostprocessor.dll") =>
        Build(moduleName, (module, _) =>
        {
            var unityEditor = AddAssemblyRef(module, "UnityEditor");
            var baseRef = new TypeReference(module, unityEditor, "UnityEditor", "AssetPostprocessor");
            module.TopLevelTypes.Add(new TypeDefinition("", "MyProcessor", TypeAttributes.Public, baseRef));
        });

    // --- helpers ---

    private static AssemblyReference AddAssemblyRef(ModuleDefinition module, string name)
    {
        var r = new AssemblyReference(name, new Version(0, 0, 0, 0));
        module.AssemblyReferences.Add(r);
        return r;
    }

    private static void AddCallMethod(ModuleDefinition module, TypeDefinition type, string name,
        IEnumerable<CilInstruction> body)
    {
        var method = new MethodDefinition(name,
            MethodAttributes.Public | MethodAttributes.Static,
            MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
        method.CilMethodBody = new CilMethodBody(method);
        foreach (var instr in body)
            method.CilMethodBody.Instructions.Add(instr);
        method.CilMethodBody.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
        type.Methods.Add(method);
    }

    private static byte[] Build(string moduleName, Action<ModuleDefinition, TypeDefinition> configure)
    {
        var module = new ModuleDefinition(moduleName);
        var type = new TypeDefinition("TestMalware", "TestClass",
            TypeAttributes.Public | TypeAttributes.Class,
            module.CorLibTypeFactory.Object.ToTypeDefOrRef());
        module.TopLevelTypes.Add(type);
        configure(module, type);

        var tmp = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".dll");
        try
        {
            module.Write(tmp);
            return File.ReadAllBytes(tmp);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }
}
