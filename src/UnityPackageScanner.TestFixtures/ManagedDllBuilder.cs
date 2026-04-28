using AsmResolver;
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

    /// <summary>
    /// Creates a managed DLL whose type and method names contain control characters (0x01–0x03).
    /// This is the most reliable obfuscation signal used by ConfuserEx and similar tools.
    /// The type also carries a [System.Reflection.ObfuscationAttribute] to exercise attribute detection.
    /// </summary>
    public static byte[] WithObfuscatedNames(string moduleName = "TestObfuscated.dll") =>
        Build(moduleName, (module, _) =>
        {
            var obfType = new TypeDefinition("", "\x01\x02\x03",
                TypeAttributes.Public | TypeAttributes.Class,
                module.CorLibTypeFactory.Object.ToTypeDefOrRef());

            // Add [System.Reflection.ObfuscationAttribute] to exercise the attribute-detection path.
            var sysRuntime = AddAssemblyRef(module, "System.Runtime");
            var obfAttrRef = new TypeReference(module, sysRuntime, "System.Reflection", "ObfuscationAttribute");
            obfType.CustomAttributes.Add(new CustomAttribute(
                new MemberReference(obfAttrRef, ".ctor",
                    MethodSignature.CreateInstance(module.CorLibTypeFactory.Void))));

            var method = new MethodDefinition("\x04\x05",
                MethodAttributes.Public | MethodAttributes.Static,
                MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
            method.CilMethodBody = new CilMethodBody(method);
            method.CilMethodBody.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
            obfType.Methods.Add(method);

            module.TopLevelTypes.Add(obfType);
        });

    /// <summary>
    /// Creates a managed DLL where the type name is normal but method names contain control characters.
    /// Tests the method-level obfuscation detection path separately from the type-level one.
    /// </summary>
    public static byte[] WithObfuscatedMethodNamesOnly(string moduleName = "TestObfMethodOnly.dll") =>
        Build(moduleName, (module, _) =>
        {
            var type = new TypeDefinition("", "NormalLookingType",
                TypeAttributes.Public | TypeAttributes.Class,
                module.CorLibTypeFactory.Object.ToTypeDefOrRef());

            var method = new MethodDefinition("\x01\x02",
                MethodAttributes.Public | MethodAttributes.Static,
                MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
            method.CilMethodBody = new CilMethodBody(method);
            method.CilMethodBody.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
            type.Methods.Add(method);

            module.TopLevelTypes.Add(type);
        });

    /// <summary>
    /// Creates a managed DLL with many types and methods whose names are ≤2 characters long.
    /// Exercises the short-name ratio scoring path in ObfuscatedDllRule.
    /// </summary>
    public static byte[] WithManyShortNames(int count = 12, string moduleName = "TestShortNames.dll") =>
        Build(moduleName, (module, _) =>
        {
            for (int i = 0; i < count; i++)
            {
                var t = new TypeDefinition("", $"T{i}",
                    TypeAttributes.Public | TypeAttributes.Class,
                    module.CorLibTypeFactory.Object.ToTypeDefOrRef());

                var m = new MethodDefinition($"M{i}",
                    MethodAttributes.Public | MethodAttributes.Static,
                    MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
                m.CilMethodBody = new CilMethodBody(m);
                m.CilMethodBody.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
                t.Methods.Add(m);

                module.TopLevelTypes.Add(t);
            }
        });

    /// <summary>Creates a managed DLL with a class that inherits <c>UnityEditor.AssetPostprocessor</c>.</summary>
    public static byte[] WithAssetPostprocessor(string moduleName = "TestPostprocessor.dll") =>
        Build(moduleName, (module, _) =>
        {
            var unityEditor = AddAssemblyRef(module, "UnityEditor");
            var baseRef = new TypeReference(module, unityEditor, "UnityEditor", "AssetPostprocessor");
            module.TopLevelTypes.Add(new TypeDefinition("", "MyProcessor", TypeAttributes.Public, baseRef));
        });

    /// <summary>
    /// Creates a managed DLL with a high-entropy (pseudo-random) embedded resource.
    /// Exercises the EmbeddedEncryptedResourceRule entropy detection path.
    /// Uses a fixed seed so the bytes — and therefore the entropy — are deterministic across test runs.
    /// </summary>
    public static byte[] WithHighEntropyEmbeddedResource(
        int resourceSizeBytes = 2048,
        string moduleName = "TestHighEntropy.dll") =>
        Build(moduleName, (module, _) =>
        {
            var data = new byte[resourceSizeBytes];
            new Random(unchecked((int)0xDEADBEEFu)).NextBytes(data); // near-uniform → entropy ~7.99

            module.Resources.Add(new ManifestResource(
                "encrypted_payload",
                ManifestResourceAttributes.Private,
                new DataSegment(data)));
        });

    /// <summary>
    /// Creates a managed DLL with a small, low-entropy embedded resource (repeating bytes).
    /// Should NOT trigger EmbeddedEncryptedResourceRule.
    /// </summary>
    public static byte[] WithLowEntropyEmbeddedResource(string moduleName = "TestLowEntropy.dll") =>
        Build(moduleName, (module, _) =>
        {
            var data = new byte[1024];
            Array.Fill(data, (byte)'A'); // entropy ≈ 0 bits/byte

            module.Resources.Add(new ManifestResource(
                "string_table.resources",
                ManifestResourceAttributes.Public,
                new DataSegment(data)));
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
