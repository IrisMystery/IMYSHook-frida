import { config } from './config.js';
import * as util from './util.js';
export let chapterDicts: Record<string, string> = {};
export let nameDicts: Record<string, string> = {};


export function Init() {

    const url1 = config.transGameNovelCharaNameUrl;
    util.androidhttpGet(url1, (respdata) => nameDicts = respdata);
    const url2 = config.transGameNovelCharaSubNameUrl;
    util.androidhttpGet(url2, (respdata) => Object.assign(nameDicts, respdata));
}

export function FetchChapterTranslation(label) {
    const url = config.transGameNovelChapterUrl(label);
    util.androidhttpGet(url, (respdata) => chapterDicts[label] = respdata);
}
