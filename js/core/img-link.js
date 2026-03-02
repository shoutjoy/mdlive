/* ImgLink — IMG 버튼 클릭 시 이동할 이미지 호스팅 URL 설정 (3개 × 3곳 적용)
   localStorage 저장, 설정창(#hk-panel)에서 편집
   적용 위치: 메인(타이틀바), 이미지삽입, AI이미지 */

const DEFAULT_IMG_URL = 'https://imgbb.com/';

const ImgLink = (() => {
    const STORAGE_KEY = 'mdpro_img_links';

    function loadData() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                const d = JSON.parse(raw);
                let urls = Array.isArray(d.urls) ? d.urls.slice(0, 3) : ['', '', ''];
                if (!(urls[0] || '').trim()) urls[0] = DEFAULT_IMG_URL;
                const memos = Array.isArray(d.memos) ? d.memos.slice(0, 3) : ['', '', ''];
                let apply = { main: 0, insert: 0, ai: 0 };
                if (d.apply && typeof d.apply === 'object') {
                    apply.main = Math.max(0, Math.min(2, parseInt(d.apply.main, 10) || 0));
                    apply.insert = Math.max(0, Math.min(2, parseInt(d.apply.insert, 10) || 0));
                    apply.ai = Math.max(0, Math.min(2, parseInt(d.apply.ai, 10) || 0));
                } else if (typeof d.active === 'number') {
                    apply = { main: d.active, insert: d.active, ai: d.active };
                }
                return { urls, memos, apply };
            }
        } catch (e) {}
        return {
            urls: [DEFAULT_IMG_URL, '', ''],
            memos: ['', '', ''],
            apply: { main: 0, insert: 0, ai: 0 }
        };
    }

    function saveData(data) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        } catch (e) {}
    }

    function get(place) {
        const d = loadData();
        const idx = place === 'insert' ? d.apply.insert : place === 'ai' ? d.apply.ai : d.apply.main;
        const url = (d.urls[idx] || '').trim();
        return url || DEFAULT_IMG_URL;
    }

    function save() {
        const urls = [];
        const memos = [];
        for (let i = 0; i < 3; i++) {
            const inp = document.getElementById('hk-img-link-' + i);
            const memo = document.getElementById('hk-img-link-memo-' + i);
            urls.push(inp ? (inp.value || '').trim().split('\n')[0].trim() : '');
            memos.push(memo ? (memo.value || '').trim() : '');
        }
        let main = 0, insert = 0, ai = 0;
        for (let i = 0; i < 3; i++) {
            const chkMain = document.getElementById('hk-img-link-main-' + i);
            const chkInsert = document.getElementById('hk-img-link-insert-' + i);
            const chkAi = document.getElementById('hk-img-link-ai-' + i);
            if (chkMain && chkMain.checked) main = i;
            if (chkInsert && chkInsert.checked) insert = i;
            if (chkAi && chkAi.checked) ai = i;
        }
        saveData({ urls, memos, apply: { main, insert, ai } });
    }

    function loadToPanel() {
        const d = loadData();
        for (let i = 0; i < 3; i++) {
            const inp = document.getElementById('hk-img-link-' + i);
            const memo = document.getElementById('hk-img-link-memo-' + i);
            const chkMain = document.getElementById('hk-img-link-main-' + i);
            const chkInsert = document.getElementById('hk-img-link-insert-' + i);
            const chkAi = document.getElementById('hk-img-link-ai-' + i);
            if (inp) inp.value = (i === 0 && !(d.urls[0] || '').trim()) ? DEFAULT_IMG_URL : (d.urls[i] || '');
            if (memo) memo.value = (d.memos && d.memos[i]) ? d.memos[i] : '';
            if (chkMain) chkMain.checked = (d.apply.main === i);
            if (chkInsert) chkInsert.checked = (d.apply.insert === i);
            if (chkAi) chkAi.checked = (d.apply.ai === i);
        }
        function bindRadio(name, idPrefix) {
            for (let i = 0; i < 3; i++) {
                const chk = document.getElementById(idPrefix + i);
                if (chk) {
                    chk.onchange = function() {
                        if (chk.checked) {
                            for (let j = 0; j < 3; j++) {
                                const c = document.getElementById(idPrefix + j);
                                if (c && c !== chk) c.checked = false;
                            }
                        }
                    };
                }
            }
        }
        bindRadio('main', 'hk-img-link-main-');
        bindRadio('insert', 'hk-img-link-insert-');
        bindRadio('ai', 'hk-img-link-ai-');
    }

    function open() {
        const url = get('main');
        if (url) window.open(url, '_blank');
    }
    function openUpload() {
        const url = get('insert');
        if (url) window.open(url, '_blank');
    }
    function openUploadAi() {
        const url = get('ai');
        if (url) window.open(url, '_blank');
    }

    function openAt(idx) {
        const inp = document.getElementById('hk-img-link-' + idx);
        const url = (inp && inp.value ? inp.value : '').trim().split('\n')[0].trim();
        if (url) window.open(url, '_blank');
    }

    return { get, save, loadToPanel, open, openAt, openUpload, openUploadAi };
})();
