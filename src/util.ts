import * as fs from "fs";
import * as gameClass from "./gameClass.js";
import { config } from "./config.js"
import Java from "frida-java-bridge"

export function isFileExists(path) {
    try {
        return fs.statSync(path).isFile
    }
    catch {
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

export function androidhttpGet(targetUrl: string): Promise<any> {
    return new Promise((resolve, reject) => {
        Java.perform(function () {
            try {
                var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                var URL = Java.use("java.net.URL");
                var BufferedReader = Java.use("java.io.BufferedReader");
                var StringBuilder = Java.use("java.lang.StringBuilder");
                var InputStreamReader = Java.use("java.io.InputStreamReader");

                var url = URL.$new(Java.use("java.lang.String").$new(targetUrl));
                var conn = url.openConnection();
                conn = Java.cast(conn, HttpURLConnection);
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(config.fetchTimeout);
                conn.setReadTimeout(config.fetchTimeout);
                conn.setDoInput(true);
                conn.setChunkedStreamingMode(0);
                conn.connect();

                var code = conn.getResponseCode();
                var data = null;

                if (code == 200) {
                    var inputStream = conn.getInputStream();
                    var buffer = BufferedReader.$new(InputStreamReader.$new(inputStream));
                    var sb = StringBuilder.$new();
                    var line = null;

                    while ((line = buffer.readLine()) != null) {
                        sb.append(line);
                    }

                    data = sb.toString();
                    data = JSON.parse(data);
                    resolve(data);
                } else {
                    reject("error: " + code);
                }

                conn.disconnect();
            } catch (error) {
                reject(error);
            }
        });
    });
}
