import "frida-il2cpp-bridge";

export let Csharp: Il2Cpp.Image;
export let AssetBundleModule: Il2Cpp.Image;
export let TextMeshPro: Il2Cpp.Image;
export let UnityNetworking: Il2Cpp.Image;
export let UnityCoreModule: Il2Cpp.Image;

export let NovelRoot: Il2Cpp.Class;
export let DmmABmanager: Il2Cpp.Class;
export let AssetBundle: Il2Cpp.Class;
export let TMP_FontAsset: Il2Cpp.Class;
export let UnityApplication: Il2Cpp.Class;
export let SysByte: Il2Cpp.Class;
export let SysFile: Il2Cpp.Class;
export let SysBinaryReader: Il2Cpp.Class;
export let BurikoParseScript: Il2Cpp.Class;
export let UnityWebRequest: Il2Cpp.Class;
export let MessageScrollView: Il2Cpp.Class;
export let ChoicesContent: Il2Cpp.Class;
export let TextRoot: Il2Cpp.Class;
export let AssetManager: Il2Cpp.Class;
export let ApiManager: Il2Cpp.Class;

Il2Cpp.perform(() => {
    Csharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    AssetBundleModule = Il2Cpp.domain.assembly("UnityEngine.AssetBundleModule").image;
    TextMeshPro = Il2Cpp.domain.assembly("Unity.TextMeshPro").image;
    UnityNetworking = Il2Cpp.domain.assembly("UnityEngine.UnityWebRequestModule").image;
    UnityCoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;

    SysFile = Il2Cpp.corlib.class("System.IO.File");
    SysByte = Il2Cpp.corlib.class("System.Byte");
    SysBinaryReader = Il2Cpp.corlib.class("System.IO.BinaryReader");
    AssetBundle = AssetBundleModule.class("UnityEngine.AssetBundle");
    UnityApplication = UnityCoreModule.class("UnityEngine.Application");
    TMP_FontAsset = TextMeshPro.class("TMPro.TMP_FontAsset");
    NovelRoot = Csharp.class("Hachiroku.Novel.UI.NovelRoot");
    DmmABmanager = Csharp.class("DMM.OLG.Unity.Engine.AssetBundleManager");
    BurikoParseScript = Csharp.class("Hachiroku.Novel.BurikoParseScript");
    MessageScrollView = Csharp.class("Hachiroku.Novel.UI.MessageScrollView");
    ChoicesContent = Csharp.class("Hachiroku.Novel.UI.ChoicesContent");
    TextRoot = Csharp.class("Hachiroku.Novel.UI.TextRoot");
    AssetManager = Csharp.class("Hachiroku.AssetManager");
    ApiManager = Csharp.class("Hachiroku.ApiManager");
}
);
