
import * as gameClass from "./gameClass.js";
import * as Translation from "./translation.js";
import { config } from "./config.js"

import { isFileExists, SysOpenFile2Byte } from "./util.js";

export var TMPTranslateFont;
export let ConfigPath: string;

setTimeout(Translation.Init, 5000); //for frida-gadget,some functions need to wait.

let fontName = config.fontName;
var fontPath;
let currentAdvId;

Il2Cpp.perform(() => {
    ConfigPath = gameClass.DmmABmanager.method<Il2Cpp.String>("GetAssetDataPath").invoke().toString().slice(1, -1); // original string includes ""
    fontPath = ConfigPath + '/' + fontName
});

// Hook NovelRoot.Start
Il2Cpp.perform(() => {
    gameClass.NovelRoot.method("Start").implementation = function () {
        if (isFileExists(fontPath)) {
            // the unity libs of bepinex which was used does not match the lib of game,so there is no LoadFromFile method.
            // this works but extremely slow and will timeout if in attaching.
            // abfilebytes = Il2Cpp.array(Il2Cpp.corlib.class('System.Byte'),abfile);  
            SysOpenFile2Byte(fontPath, (callback: Il2Cpp.Array<UInt64>) => {
                let abfilebytes = callback;
                let ab = gameClass.AssetBundle.method<Il2Cpp.Object>("LoadFromMemory").invoke(abfilebytes);
                TMPTranslateFont = ab.method<Il2Cpp.Object>("LoadAsset").inflate(gameClass.TMP_FontAsset).invoke(Il2Cpp.string(fontName + " SDF"));
                ab.method("Unload").invoke(false);
            });

        }
        else {
            console.error("font not found");
        }
        currentAdvId = this.method<Il2Cpp.Object>("get_Linker").invoke().method<Il2Cpp.String>("get_ScenarioId").invoke().toString().slice(1, -1);;
        console.log(currentAdvId);

        Translation.FetchChapterTranslation(currentAdvId);


        // invoke original method(Prefix)
        return this.method("Start").invoke();
    }
})

// Hook Novel_SetMssageCommand
Il2Cpp.perform(() => {
    gameClass.BurikoParseScript.method("_SetMssageCommand").implementation = function (lineNum, oline: Il2Cpp.String, isSelectedCaseArea, caseCount) {
        let line = oline.toString().slice(1, -1);
        if (Translation.chapterDicts.hasOwnProperty(currentAdvId) && line.includes("「") && line.endsWith("」")) {
            const idx = line.indexOf("「");
            const name = line.substring(0, idx);
            const text = line.substring(idx);

            let full = "";

            const name_replace = Translation.nameDicts[name];
            if (name_replace !== undefined) {
                full = !name_replace.trim() ? text : name_replace;
            }

            const text_replace = Translation.chapterDicts[currentAdvId][text];
            if (text_replace !== undefined) {
                let final_text = "「" + text_replace.substring(1, text_replace.length - 1).replace("「", "『").replace("」", "』") + "」";
                full += final_text;
            }

            if (full) line = full;
        } else {
            const text_replace = Translation.chapterDicts[currentAdvId][line];
            if (text_replace !== undefined) {
                line = text_replace.replace("「", "『").replace("」", "』");
            }
        }
        // invoke original method(Prefix)
        return this.method("_SetMssageCommand").invoke(lineNum, Il2Cpp.string(line), isSelectedCaseArea, caseCount);
    }
}
)

// Hook Novel_ToParamList
Il2Cpp.perform(() => {
    gameClass.BurikoParseScript.method("_ToParamList").implementation = function (oparam: Il2Cpp.String) {
        var param = oparam.toString().slice(1, -1);
        const re = /{(.*)}/;
        const match = param.match(re);
        if (match) {
            for (let i = 0; i < match.length; i++) {
                const options = match[i].split(",");

                for (let i2 = 0; i2 < options.length; i2++) {
                    if (Translation.chapterDicts.hasOwnProperty(currentAdvId)) {
                        const text_replace = Translation.chapterDicts[currentAdvId][options[i2]];
                        if (text_replace !== undefined) {
                            const option_tr = text_replace.trim() === "" ? options[i2] : text_replace;
                            param = param.replace(options[i2], option_tr);
                        }
                    }
                }
            }
        }
        // invoke original method(Prefix)
        return this.method("_ToParamList").invoke(Il2Cpp.string(param));
    }
})

//Hook CreateItem
Il2Cpp.perform(() => {
    gameClass.MessageScrollView.method("CreateItem").implementation = function (item: Il2Cpp.Object) {
        if (TMPTranslateFont) {
            item.field<Il2Cpp.Object>("_name").value.method("set_font").invoke(TMPTranslateFont);
            item.field<Il2Cpp.Object>("_message").value.method("set_font").invoke(TMPTranslateFont);
        }
        // invoke original method(Prefix)
        return this.method("CreateItem").invoke(item);
    }
})

//Hook SetChoiceButtonText
Il2Cpp.perform(() => {
    gameClass.ChoicesContent.method("SetChoiceButtonText").implementation = function (index, text) {
        // invoke original method(Postfix)
        let result = this.method("SetChoiceButtonText").invoke(index, text);
        if (TMPTranslateFont) {
            for (const value of this.field<Il2Cpp.Array<Il2Cpp.Object>>("choiceTextList").value) {
                value.method("set_font").invoke(TMPTranslateFont);
            }
        }
        return result;
    }
})

//Hook DeleteRuby
Il2Cpp.perform(() => {
    gameClass.TextRoot.method("DeleteRuby").implementation = function () {
        // invoke original method(Postfix)
        let result = this.method("DeleteRuby").invoke();
        if (TMPTranslateFont) {
            if (!this.method<Il2Cpp.Object>("get_CharaName").invoke().isNull()) this.method<Il2Cpp.Object>("get_CharaName").invoke().method("set_font").invoke(TMPTranslateFont);
            if (!this.method<Il2Cpp.Object>("get_Message").invoke().isNull()) this.method<Il2Cpp.Object>("get_Message").invoke().method("set_font").invoke(TMPTranslateFont);
        }
        return result;
    }
})