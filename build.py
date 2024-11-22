import lief
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


def process_apk():
    subprocess.run(['apktool', 'd', '-f', '-r', '-s', apk_file, '-o', './imys_r_programdata'], check=True, shell=is_windows)
    shutil.rmtree('./imys_r_programdata/lib/armeabi-v7a')  # remove unsupported armv7
    shutil.copy('./frida/gadget-android-arm64.so', './imys_r_programdata/lib/arm64-v8a/libgadget.so')
    shutil.copy('./frida/libgadget.config.so', './imys_r_programdata/lib/arm64-v8a/libgadget.config.so')
    shutil.copy('./dist/_.js', './imys_r_programdata/lib/arm64-v8a/libgadget.js.so')
    lib = lief.parse('./imys_r_programdata/lib/arm64-v8a/libil2cpp.so')
    lib.add_library('libgadget.so')
    lib.write('./imys_r_programdata/lib/arm64-v8a/libil2cpp.so')
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
    process_apk()


if __name__ == '__main__':
    main()
