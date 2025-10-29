# IMYSHook-frida

[IMYSHook](https://github.com/Irismystery/IMYSHook) 的翻译功能使用frida的重新实现。主要用于生成安卓版本。

## 下载

见 [Releases](https://github.com/IrisMystery/IMYSHook-frida/releases)。  
直接安装即可使用。
> [!NOTE]
> 如果你没有对系统应用过核心破解且安装了FANZA商店版游戏，则需要先卸载已安装的游戏。  
### 翻译没有生效？

以下步骤可能有帮助：
- 关闭miui优化，以及其他ROM若有自身可关闭的优化，请务必关闭。
- [修改汉化apk的包名后再安装。](https://www.cnblogs.com/wxy13644813114/p/13608281.html)
- 卸载新版ART。`adb pm uninstall com.google.android.art`。[此步骤可以仅用手机实现。](https://www.cups.moe/archives/android-adb.html)
  
## 配置

从 v1.2.0 开始，首次运行会生成 ```Android/data/jp.co.dmm.dmmgames.imys_r/files/config.json```，你可以在该文件中配置该mod的行为。  
当前的可配置项如下:
| 名称                | 说明                                                                                                                                      |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| isFakeLatestVersion | 是否屏蔽游戏的强制更新提示。注意尽管经长期测试这应该是安全的，但依然有封号风险。                                                          |
| isEnableTranslation | 是否启用翻译。                                                                                                                              |
| fontName            | 自定义翻译字体。此处填写字体名称，你需要用与游戏版本相同unity生成安卓编译的TMP字体包并放在`Android/data/jp.co.dmm.dmmgames.imys_r/files/il2cpp`下。 |

## 编译

依赖:  
Java  
Apktool  
Python  
Node  
Frida-gadget (放入frida/gadget-android-arm64.so)  
Android SDK Build Tools (需要在$PATH中)

```shell
npm i
pip install -r requirements.txt
python build.py
```
