using AsmResolver.DotNet;

namespace UnityPackageScanner.TestFixtures;

/// <summary>
/// Generates minimal binary blobs for testing native-binary detection rules.
/// </summary>
public static class NativeBinaryBuilder
{
    /// <summary>Minimal ELF64 shared library (magic bytes only; enough for magic-byte detection).</summary>
    public static byte[] CreateElf64() =>
    [
        // ELF magic
        0x7F, 0x45, 0x4C, 0x46,
        0x02,                                             // 64-bit
        0x01,                                             // little-endian
        0x01,                                             // ELF version
        0x00,                                             // OS/ABI: System V
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
        0x03, 0x00,                                       // e_type: ET_DYN
        0x3E, 0x00,                                       // e_machine: x86-64
        0x01, 0x00, 0x00, 0x00,                           // e_version: 1
    ];

    /// <summary>Minimal 64-bit Mach-O dylib (little-endian magic; enough for magic-byte detection).</summary>
    public static byte[] CreateMachO64() =>
    [
        0xCF, 0xFA, 0xED, 0xFE, // MH_MAGIC_64 LE
        0x0C, 0x00, 0x00, 0x01, // cputype: ARM64
        0x00, 0x00, 0x00, 0x00, // cpusubtype: 0
        0x06, 0x00, 0x00, 0x00, // filetype: MH_DYLIB
        0x00, 0x00, 0x00, 0x00, // ncmds: 0
        0x00, 0x00, 0x00, 0x00, // sizeofcmds: 0
        0x00, 0x00, 0x00, 0x00, // flags: 0
        0x00, 0x00, 0x00, 0x00, // reserved (64-bit)
    ];

    /// <summary>
    /// MZ magic bytes without a valid PE structure. AsmResolver.PEImage.FromBytes will throw,
    /// causing NativePluginRule.IsNativePe to return true (conservative/safe default).
    /// </summary>
    public static byte[] CreateNativePeStub() =>
    [
        0x4D, 0x5A,             // MZ magic
        0x90, 0x00, 0x03, 0x00, // DOS header stub (no valid PE offset)
        0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0xFF, 0xFF,
        0x00, 0x00,
    ];

    /// <summary>
    /// Creates a minimal valid managed .NET assembly using AsmResolver.
    /// The returned bytes start with MZ and contain a CLR directory;
    /// NativePluginRule will recognize it as managed and skip it.
    /// </summary>
    public static byte[] CreateManagedDll(string moduleName = "TestManaged.dll")
    {
        var tmp = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".dll");
        try
        {
            new ModuleDefinition(moduleName).Write(tmp);
            return File.ReadAllBytes(tmp);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }
}
