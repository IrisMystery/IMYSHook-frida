import lief
import subprocess
import shutil
import os
import requests

apkUrl = 'https://dl-app.games.dmm.com/android/jp.co.dmm.dmmgames.imys_r'
apk_file = 'imys_r.apk'


def process_apk():
    subprocess.run(['apktool', 'd', '-f', apk_file, '-o', 'imys_r_programdata'], check=True, shell=True)
    shutil.copy('frida/gadget-android-arm64.so', 'imys_r_programdata/lib/arm64-v8a/libgadget.so')
    shutil.copy('frida/libgadget.config.so', 'imys_r_programdata/lib/arm64-v8a/libgadget.config.so')
    shutil.copy('dist/_.js', 'imys_r_programdata/lib/arm64-v8a/libgadget.js.so')
    lib = lief.parse('imys_r_programdata/lib/arm64-v8a/libil2cpp.so')
    lib.add_library('libgadget.so')
    lib.write('imys_r_programdata/lib/arm64-v8a/libil2cpp.so')
    subprocess.run(['apktool', 'b', 'imys_r_programdata', '-f', '-o', 'dist/imys_r.apk'], check=True, shell=True)
    if not os.path.exists('imys.keystore'):
        subprocess.run(['keytool', '-genkey', '-v', '-keystore', 'imys.keystore', '-alias', 'imys', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000'], check=True, shell=True)
    subprocess.run(['apksigner', 'sign', '--ks', 'imys.keystore', '--ks-pass', 'pass:123456', 'dist/imys_r.apk'], check=True, shell=True)


def main():
    if not os.path.exists(apk_file):
        response = requests.get(apkUrl)
        with open(apk_file, 'wb') as f:
            f.write(response.content)
    subprocess.run(['npm', 'run', 'build'], check=True, shell=True)
    process_apk()


if __name__ == '__main__':
    main()
