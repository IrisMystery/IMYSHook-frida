function logInAndroid(log) {
    Java.perform(() => {
        let Log = Java.use("android.util.Log");
        let TAG_L = "[imyshook-frida]";
        Log.v(TAG_L, log);
    });
}

(function hijackConsole() {
    let originalLog = console.log;
    let originalError = console.error;

    console.log = function (...args) {
        let message = args.map(arg => {
            if (typeof arg === "object") {
                return JSON.stringify(arg, null, 2);
            }
            return String(arg);
        }).join(" ");

        logInAndroid(message);

        originalLog.apply(console, args);
    };

    console.error = function (...args) {
        let message = args.map(arg => {
            if (typeof arg === "object") {
                return JSON.stringify(arg, null, 2);
            }
            return String(arg);
        }).join(" ");

        logInAndroid(`[ERROR] ${message}`);
        originalError.apply(console, args);
    };
})();

import "frida-il2cpp-bridge";


import "./gameClass.js";
import { loadConfigAsync, config } from "./config.js";
import * as patch from "./patch.js";

async function main() {
    await loadConfigAsync();
    console.log(JSON.stringify(config, null, 2));
    Il2Cpp.installExceptionListener("all")
    patch.main();
}
main()
