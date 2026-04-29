namespace UnityPackageScanner.Core.Analysis;

public static class KnownRuleIds
{
    public const string ObfuscatedDll = "UPS001";
    public const string AutoExecuteEditor = "UPS002";
    public const string NativePlugin = "UPS003";
    public const string PathAnomaly = "UPS004";
    public const string NetworkAccess = "UPS005";
    public const string ProcessSpawn = "UPS006";
    public const string ReflectionLoad = "UPS007";
    public const string SuspiciousPInvoke = "UPS008";
    public const string EmbeddedEncryptedResource = "UPS009";
    public const string HiddenFolder = "UPS010";
    public const string HashBlocklist = "UPS011";
    public const string SuspiciousFileType = "UPS012";
    public const string GuidCollision = "UPS013";
    public const string PlatformConfigAccess = "UPS014";
    public const string AlphaHijackFolder = "UPS015";
    public const string BinaryMasquerade = "UPS016";
    public const string PackageInfo = "UPS100";
}
