/* ImgLink — IMG 버튼 클릭 시 이동할 이미지 호스팅 URL 설정 (3개, 체크된 것이 메인)
   localStorage 저장, 설정창(#hk-panel)에서 편집 */

const DEFAULT_IMG_URL = 'https://imgbb.com/';

const ImgLink = (() => {
    const STORAGE_KEY = 'mdpro_img_links';

    function loadData() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                const d = JSON.parse(raw);
                return {
                    active: Math.max(0, Math.min(2, parseInt(d.active, 10) || 0)),
                    urls: Array.isArray(d.urls) ? d.urls.slice(0, 3) : ['', '', '']
                };
            }
        } catch (e) {}
        return { active: 0, urls: [DEFAULT_IMG_URL, '', ''] };
    }

    function saveData(data) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        } catch (e) {}
    }

    function get() {
        const d = loadData();
        const url = (d.urls[d.active] || '').trim();
        return url || DEFAULT_IMG_URL;
    }

    function save() {
        const urls = [];
        for (let i = 0; i < 3; i++) {
            const inp = document.getElementById('hk-img-link-' + i);
            urls.push(inp ? (inp.value || '').trim() : '');
        }
        let active = 0;
        for (let i = 0; i < 3; i++) {
            const chk = document.getElementById('hk-img-link-chk-' + i);
            if (chk && chk.checked) { active = i; break; }
        }
        saveData({ active, urls });
    }

    function loadToPanel() {
        const d = loadData();
        for (let i = 0; i < 3; i++) {
            const inp = document.getElementById('hk-img-link-' + i);
            const chk = document.getElementById('hk-img-link-chk-' + i);
            if (inp) inp.value = d.urls[i] || '';
            if (chk) chk.checked = (d.active === i);
        }
        /* 체크박스: 하나만 선택 (라디오처럼) */
        for (let i = 0; i < 3; i++) {
            const chk = document.getElementById('hk-img-link-chk-' + i);
            if (chk) {
                chk.onchange = function() {
                    if (chk.checked) {
                        for (let j = 0; j < 3; j++) {
                            const c = document.getElementById('hk-img-link-chk-' + j);
                            if (c && c !== chk) c.checked = false;
                        }
                    }
                };
            }
        }
    }

    function open() {
        const url = get();
        if (url) window.open(url, '_blank');
    }

    function openAt(idx) {
        const inp = document.getElementById('hk-img-link-' + idx);
        const url = (inp && inp.value ? inp.value : '').trim();
        if (url) window.open(url, '_blank');
    }

    return { get, save, loadToPanel, open, openAt };
})();
