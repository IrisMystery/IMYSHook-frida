import * as fs from "fs";
import { isFileExists } from "./util.js";

interface ConfigType {
    isFakeLatestVersion: boolean; // disable game force update.Although it's safe through a long time test, this may increase the risk of account ban.
    isEnableTranslation: boolean; // as it name says.
    transGameNovelCharaNameUrl: string;
    transGameNovelCharaSubNameUrl: string;
    transGameNovelChapterUrl: (label: string) => string;
    fontName: string; // if you want load other unity TMPfont assetbundle, put it into Android/data/jp.co.dmm.dmmgames.imys_r/files/il2cpp and change the filename here.
    fetchTimeout : Number; // time allowed to fetch translation
}

const DEFAULT_CONFIG: ConfigType = {
    "isFakeLatestVersion": false,
    "isEnableTranslation": true,
    "transGameNovelCharaNameUrl": "https://translation.lolida.best/download/imys/imys_name/zh_Hant/?format=json",
    "transGameNovelCharaSubNameUrl": "https://translation.lolida.best/download/imys/imys_subname/zh_Hant/?format=json",
    "transGameNovelChapterUrl": (label) => {
        return `https://translation.lolida.best/download/imys/${label}/zh_Hant/?format=json`
    },
    "fontName": "notosanscjktc",
    "fetchTimeout":10000,
};

export let config: ConfigType = { ...DEFAULT_CONFIG };
export function loadConfigAsync(): Promise<ConfigType> { 
    return new Promise((resolve) => {
        setTimeout(() => {
            Il2Cpp.perform(() =>{
                                        var configFilePath;
                    configFilePath = `${Il2Cpp.application.dataPath}/config.json`;
                    let currentConfig: ConfigType = { ...DEFAULT_CONFIG }; // Start with default config
                    console.log(configFilePath)
                    if (isFileExists(configFilePath)) {
                        const configFileContent: string = fs.readFileSync(configFilePath, 'utf8') as string;
                        try {
                            const loadedConfig: ConfigType = JSON.parse(configFileContent);
                            // Merge loadedConfig into currentConfig, prioritizing loaded values
                            Object.assign(currentConfig, loadedConfig);
                            console.log(`[Config] Successfully read config file: ${configFilePath}`);
                        } catch (e: any) { // Use 'any' for 'e' in catch block for broader compatibility
                            console.error(`[Config] Failed to parse config file: ${e.message}. Using default config.`);
                            // If parsing fails, currentConfig remains DEFAULT_CONFIG
                        }
                    } else {
                        console.warn(`[Config] Config file not found: ${configFilePath}. Creating default config file.`);
                    }

                    // Always write back the merged configuration (which includes new defaults or loaded values)
                    try {
                        fs.writeFileSync(configFilePath, JSON.stringify(currentConfig, null, 2));
                        console.log(`[Config] Successfully created/updated config file: ${configFilePath}`);
                    } catch (writeError: any) { // Use 'any' for 'writeError'
                        console.error(`[Config] Failed to write config file: ${writeError.message}`);
                    }

                    Object.assign(config, currentConfig);
                    console.log("[Config] Current configuration:", JSON.stringify(config, null, 2));

            resolve(config)
            });
        }, 4000)
    }
    )
}
