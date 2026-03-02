/* FindHighlight — 찾기 하이라이트 색상·농도 설정 (localStorage)
   #hk-find-hl-row 입력값 저장/로드, CSS 변수 적용 */

const FindHighlight = (() => {
    const STORAGE_KEY = 'mdpro_find_hl';
    let _rangeBound = false;

    function hexToRgb(hex) {
        const m = hex.replace(/^#/, '').match(/.{2}/g);
        return m ? m.map(x => parseInt(x, 16)) : [255, 200, 0];
    }
    function hexToRgba(hex, a) {
        const [r, g, b] = hexToRgb(hex);
        return `rgba(${r},${g},${b},${a})`;
    }

    function loadData() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                const d = JSON.parse(raw);
                return {
                    color: d.color || '#ffc800',
                    opacity: Math.max(10, Math.min(100, parseInt(d.opacity, 10) || 85)) / 100,
                    currentColor: d.currentColor || '#b4b4b4',
                    currentOpacity: Math.max(10, Math.min(100, parseInt(d.currentOpacity, 10) || 55)) / 100
                };
            }
        } catch (e) {}
        return { color: '#ffc800', opacity: 0.85, currentColor: '#b4b4b4', currentOpacity: 0.55 };
    }

    function saveData(d) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                color: d.color,
                opacity: Math.round(d.opacity * 100),
                currentColor: d.currentColor,
                currentOpacity: Math.round(d.currentOpacity * 100)
            }));
        } catch (e) {
            console.warn('FindHighlight: 저장 실패 (Tracking Prevention 등)', e);
        }
    }

    function applyToDom(d) {
        const root = document.documentElement;
        if (!root) return;
        root.style.setProperty('--find-hl-color', d.color);
        root.style.setProperty('--find-hl-bg', hexToRgba(d.color, d.opacity));
        root.style.setProperty('--find-hl-border', hexToRgba(d.color, d.opacity * 0.6));
        root.style.setProperty('--find-hl-current-color', d.currentColor);
        root.style.setProperty('--find-hl-current-bg', hexToRgba(d.currentColor, d.currentOpacity));
        root.style.setProperty('--find-hl-current-border', hexToRgba(d.currentColor, d.currentOpacity * 0.7));
    }

    function save() {
        const colorEl = document.getElementById('hk-find-hl-color');
        const opacityEl = document.getElementById('hk-find-hl-opacity');
        const currentColorEl = document.getElementById('hk-find-hl-current-color');
        const currentOpacityEl = document.getElementById('hk-find-hl-current-opacity');
        const color = (colorEl && colorEl.value) ? colorEl.value : '#ffc800';
        const opacity = (opacityEl && opacityEl.value) ? parseInt(opacityEl.value, 10) / 100 : 0.85;
        const currentColor = (currentColorEl && currentColorEl.value) ? currentColorEl.value : '#b4b4b4';
        const currentOpacity = (currentOpacityEl && currentOpacityEl.value) ? parseInt(currentOpacityEl.value, 10) / 100 : 0.55;
        const d = { color, opacity, currentColor, currentOpacity };
        saveData(d);
        applyToDom(d);
        if (typeof App !== 'undefined' && App.updateFindHighlight) App.updateFindHighlight();
    }

    function loadToPanel() {
        const d = loadData();
        const colorEl = document.getElementById('hk-find-hl-color');
        const opacityEl = document.getElementById('hk-find-hl-opacity');
        const opacityValEl = document.getElementById('hk-find-hl-opacity-val');
        const currentColorEl = document.getElementById('hk-find-hl-current-color');
        const currentOpacityEl = document.getElementById('hk-find-hl-current-opacity');
        const currentOpacityValEl = document.getElementById('hk-find-hl-current-opacity-val');
        if (colorEl) colorEl.value = d.color;
        if (opacityEl) {
            opacityEl.value = Math.round(d.opacity * 100);
            if (opacityValEl) opacityValEl.textContent = Math.round(d.opacity * 100) + '%';
        }
        if (currentColorEl) currentColorEl.value = d.currentColor;
        if (currentOpacityEl) {
            currentOpacityEl.value = Math.round(d.currentOpacity * 100);
            if (currentOpacityValEl) currentOpacityValEl.textContent = Math.round(d.currentOpacity * 100) + '%';
        }
        if (!_rangeBound) {
            _rangeBound = true;
            ['hk-find-hl-opacity', 'hk-find-hl-current-opacity'].forEach((rangeId, i) => {
                const valId = i === 0 ? 'hk-find-hl-opacity-val' : 'hk-find-hl-current-opacity-val';
                const r = document.getElementById(rangeId);
                const v = document.getElementById(valId);
                if (r && v) r.addEventListener('input', () => { v.textContent = r.value + '%'; });
            });
        }
    }

    function init() {
        applyToDom(loadData());
    }

    return { save, loadToPanel, init };
})();
