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

Il2Cpp.installExceptionListener("all")

import "./gameClass.js";
import "./patch.js";

