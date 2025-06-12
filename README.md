# IMYSHook-frida

[IMYSHook](https://github.com/Irismystery/IMYSHook) 的翻译功能使用frida的重新实现。主要用于生成安卓版本。

## 下载

见 [Releases](https://github.com/IrisMystery/IMYSHook-frida/releases)。  
直接安装即可使用。
> [!NOTE]
> 如果你没有对系统应用过核心破解且安装了FANZA商店版游戏，则需要先卸载已安装的游戏。  

## 配置

从 v1.2.0 开始，你可以在 ```Android/data/jp.co.dmm.dmmgames.imys_r/files/config.json``` 中配置该mod的行为。关于配置项的说明请阅读 ```src/config.ts```。

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
