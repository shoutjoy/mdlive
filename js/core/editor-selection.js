/* EditorSelection — 에디터 텍스트 선택 영역 색상·농도 설정 (localStorage)
   #hk-selection-color, #hk-selection-opacity 저장/로드, CSS 변수 적용 */

const EditorSelection = (() => {
    const STORAGE_KEY = 'mdpro_editor_selection';
    let _opacityBound = false;

    function hexToRgba(hex, a) {
        const m = (hex || '#7c6af7').replace(/^#/, '').match(/.{2}/g);
        const [r, g, b] = m ? m.map(x => parseInt(x, 16)) : [124, 106, 247];
        return `rgba(${r},${g},${b},${a})`;
    }

    function loadData() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                const d = JSON.parse(raw);
                return {
                    color: d.color || '#7c6af7',
                    opacity: Math.max(5, Math.min(100, parseInt(d.opacity, 10) || 25)) / 100
                };
            }
        } catch (e) {}
        return { color: '#7c6af7', opacity: 0.25 };
    }

    function applyToDom(d) {
        const root = document.documentElement;
        if (!root) return;
        root.style.setProperty('--editor-selection-bg', hexToRgba(d.color, d.opacity));
    }

    function save() {
        const colorEl = document.getElementById('hk-selection-color');
        const opacityEl = document.getElementById('hk-selection-opacity');
        const color = (colorEl && colorEl.value) ? colorEl.value : '#7c6af7';
        const opacity = (opacityEl && opacityEl.value) ? parseInt(opacityEl.value, 10) / 100 : 0.25;
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({ color, opacity: Math.round(opacity * 100) }));
        } catch (e) {}
        applyToDom({ color, opacity });
    }

    function loadToPanel() {
        const d = loadData();
        const colorEl = document.getElementById('hk-selection-color');
        const opacityEl = document.getElementById('hk-selection-opacity');
        const opacityValEl = document.getElementById('hk-selection-opacity-val');
        if (colorEl) colorEl.value = d.color;
        if (opacityEl) {
            opacityEl.value = Math.round(d.opacity * 100);
            if (opacityValEl) opacityValEl.textContent = Math.round(d.opacity * 100) + '%';
        }
        if (!_opacityBound) {
            _opacityBound = true;
            const r = document.getElementById('hk-selection-opacity');
            const v = document.getElementById('hk-selection-opacity-val');
            if (r && v) r.addEventListener('input', () => { v.textContent = r.value + '%'; });
        }
    }

    function init() {
        applyToDom(loadData());
    }

    return { save, loadToPanel, init };
})();
