export let config = {
    "fontName": "fakepearl-medium",
    "transGameNovelCharaNameUrl": "https://translation.lolida.best/download/imys/imys_name/zh_Hant/?format=json",
    "transGameNovelCharaSubNameUrl": "https://translation.lolida.best/download/imys/imys_subname/zh_Hant/?format=json",
    "transGameNovelChapterUrl": (label) => {
        return `https://translation.lolida.best/download/imys/${label}/zh_Hant/?format=json`
    }
}