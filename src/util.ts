import * as fs from "fs";
import * as gameClass from "./gameClass.js";

export function isFileExists(path) {
    try {
        return fs.statSync(path).isFile
    } catch {
        return false
    }
}

export function SysOpenFile2Byte(path, callback) {
    Il2Cpp.perform(() => {
        let fsfile = gameClass.SysFile.method<Il2Cpp.Object>("OpenRead").invoke(Il2Cpp.string(path))
        let brfile = gameClass.SysBinaryReader.new()
        brfile.method<Il2Cpp.Object>(".ctor").invoke(fsfile);
        var filebytes = brfile.method<Il2Cpp.Array<UInt64>>("ReadBytes").invoke(Number(fsfile.method("get_Length").invoke()));
        callback(filebytes);
    })
}

export function netHttpGet(targetUrl: string): Promise<any> {
    return new Promise((resolve, reject) => {
        try {
            const request = gameClass.WebRequest.method<Il2Cpp.Object>('Create').overload('System.String').invoke(Il2Cpp.string(targetUrl));
            const response = request.method<Il2Cpp.Object>('GetResponse').invoke();
            const respStream = response.method<Il2Cpp.Object>('GetResponseStream').invoke();
            const reader = gameClass.SysStreamReader.new()
            reader.method<Il2Cpp.Object>(".ctor").overload('System.IO.Stream').invoke(respStream);
            const text = reader.method<Il2Cpp.Object>('ReadToEnd').invoke();
            let data = text.toString().replace(/^"|"$/g, '');
            data = JSON.parse(data);
            resolve(data)
        } catch (e) {
            console.error('Failed to get ' + targetUrl + '. Error: ' + e.toString());
            reject(e);
        }

        reject('Failed to get ' + targetUrl);
    });
}
