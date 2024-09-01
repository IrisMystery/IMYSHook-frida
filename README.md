# IMYSHook-frida

[IMYSHook](https://github.com/Irismystery/IMYSHook) 的翻译功能使用frida的重新实现。主要用于生成安卓版本。

## 下载

见 [Releases](https://github.com/IrisMystery/IMYSHook-frida/releases)。  
直接安装即可使用。  

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
