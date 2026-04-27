namespace UnityPackageScanner.Core.Models;

public enum DetectedType
{
    Unknown,
    CSharpSource,
    ManagedDll,
    NativePE,
    NativeElf,
    NativeMachO,
    Texture,
    Model,
    Audio,
    Scene,
    Prefab,
    AnimationClip,
    Material,
    Shader,
    Other,
}
