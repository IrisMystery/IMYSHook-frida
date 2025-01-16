import glob
import subprocess
import shutil
import os
import requests
import platform
import base64

apkUrl = 'https://dl-app.games.dmm.com/android/jp.co.dmm.dmmgames.imys_r'
apk_file = './imys_r.apk'
fontName = 'notosanscjktc'
is_windows = platform.system() == 'Windows'

# smali inject
inject_code = """invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    const-string v0, "gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
"""


def process_apk(method='lief'):
    """
    Args:
        method (str, optional): Can be 'JNI' or 'lief'. Defaults to 'lief'.Can be set by environment variable 'app_inject_method'.
    """
    match method:
        case 'lief':
            import lief
            subprocess.run(['apktool', 'd', '-f', '-r', '-s', apk_file, '-o', './imys_r_programdata'], check=True, shell=is_windows)
            lib = lief.parse('./imys_r_programdata/lib/arm64-v8a/libil2cpp.so')
            lib.add_library('libgadget.so')
            lib.write('./imys_r_programdata/lib/arm64-v8a/libil2cpp.so')
        case 'JNI':
            subprocess.run(['apktool', 'd', '-f', '-r', apk_file, '-o', './imys_r_programdata'], check=True, shell=is_windows)
            target_smali = glob.glob('./imys_r_programdata/*/com/unity3d/player/UnityPlayerActivity.smali')[0]
            with open(target_smali, 'r+') as f:
                text = f.read()
                text = text.replace('invoke-direct {p0}, Landroid/app/Activity;-><init>()V', inject_code)
                f.seek(0)
                f.write(text)
                f.truncate()
        case _:
            raise ValueError('Invalid method')

    shutil.copy('./frida/gadget-android-arm64.so', './imys_r_programdata/lib/arm64-v8a/libgadget.so')
    shutil.copy('./frida/libgadget.config.so', './imys_r_programdata/lib/arm64-v8a/libgadget.config.so')
    shutil.copy('./dist/_.js', './imys_r_programdata/lib/arm64-v8a/libgadget.js.so')

    shutil.rmtree('./imys_r_programdata/lib/armeabi-v7a')  # remove unsupported armv7
    # copy fonts
    if not os.path.exists(f"./res/{fontName}"):
        os.makedirs("./res", exist_ok=True)
        with open(f'./res/{fontName}', 'wb') as f:
            f.write(requests.get(f'https://github.com/IrisMystery/IMYSHook-frida/releases/download/v0.9.0/{fontName}').content)
    shutil.copy(f'./res/{fontName}', f'./imys_r_programdata/assets/bin/Data/Managed/{fontName}')
    subprocess.run(['apktool', 'b', './imys_r_programdata', '-f', '-o', './dist/imys_r.apk'], check=True, shell=is_windows)
    if not os.getenv("GITHUB_ACTIONS"):
        if not os.path.exists('imys.keystore'):
            subprocess.run(['keytool', '-genkey', '-v', '-keystore', './imys.keystore', '-alias', 'imys', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000'], check=True, shell=is_windows)
        subprocess.run(['apksigner', 'sign', '--ks', 'imys.keystore', '--ks-pass', 'pass:123456', 'dist/imys_r.apk'], check=True, shell=is_windows)
    else:
        build_tools_version = '35.0.0'
        keystore = os.getenv("KEYSTORE")
        with open('imys.keystore', 'wb') as f:
            f.write(base64.b64decode(keystore))
        subprocess.run([f"{os.getenv('ANDROID_HOME')}/build-tools/{build_tools_version}/apksigner", 'sign', '--ks', 'imys.keystore', '--ks-pass', 'pass:123456', 'dist/imys_r.apk'], check=True)


def main():
    if not os.path.exists(apk_file):
        response = requests.get(apkUrl)
        with open(apk_file, 'wb') as f:
            f.write(response.content)
    subprocess.run(['npm', 'run', 'build'], check=True, shell=is_windows)
    process_apk(method=os.environ.get('app_inject_method', 'lief'))


if __name__ == '__main__':
    main()
