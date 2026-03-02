/* EditorLineHighlight — 에디터 현재 줄 하이라이트 (색상·농도 설정 가능) */
const EditorLineHighlight = (() => {
    const STORAGE_KEY = 'mdpro_editor_line_highlight';
    const COLOR_KEY = 'mdpro_editor_line_highlight_color';
    let enabled = true;
    let _opacityBound = false;

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return enabled; }
    }

    function loadColorOpts() {
        try {
            const raw = localStorage.getItem(COLOR_KEY);
            if (raw) {
                const d = JSON.parse(raw);
                return {
                    color: d.color || '#ffffff',
                    opacity: Math.max(5, Math.min(100, parseInt(d.opacity, 10) || 20)) / 100
                };
            }
        } catch (e) {}
        return { color: '#ffffff', opacity: 0.2 };
    }

    function applyColorOpts(opts) {
        const hl = document.getElementById('editor-line-highlight');
        if (!hl) return;
        const [r, g, b] = opts.color.replace(/^#/, '').match(/.{2}/g)?.map(x => parseInt(x, 16)) || [255, 255, 255];
        hl.style.background = `rgba(${r},${g},${b},${opts.opacity})`;
    }

    function updateUI() {
        enabled = isEnabled();
        const hl = document.getElementById('editor-line-highlight');
        const btn = document.getElementById('hk-line-highlight-btn');
        const wrap = document.getElementById('hl-line-override-wrap');
        if (hl) hl.classList.toggle('vis', enabled);
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
        if (wrap) wrap.style.display = enabled ? 'inline-flex' : 'none';
        applyColorOpts(loadColorOpts());
    }

    function updateHighlight() {
        const hl = document.getElementById('editor-line-highlight');
        const ed = document.getElementById('editor');
        const lnc = document.getElementById('lnc');
        const overrideEl = document.getElementById('hl-line-override');
        if (!hl || !ed || !enabled) return;
        let lineIndex;
        const overrideVal = overrideEl && overrideEl.value.trim();
        if (overrideVal) {
            const n = parseInt(overrideVal, 10);
            lineIndex = (n > 0 ? n : 1) - 1;
        } else {
            const { line } = getCursorLineCol(ed);
            lineIndex = line - 1;
        }
        /* 줄번호(.ln)와 동일한 lineHeight·paddingTop 사용 — EZ 확대 시에도 정렬 유지 */
        let lineHeight = 21, paddingTop = 12;
        if (lnc && lnc.firstElementChild) {
            const lnStyle = window.getComputedStyle(lnc.firstElementChild);
            lineHeight = parseFloat(lnStyle.height) || parseFloat(lnStyle.lineHeight) || 21;
        }
        if (lnc) {
            const lncStyle = window.getComputedStyle(lnc);
            paddingTop = parseFloat(lncStyle.paddingTop) || 12;
        }
        const edStyle = window.getComputedStyle(ed);
        const paddingLeft = parseFloat(edStyle.paddingLeft) || 14;
        const paddingRight = parseFloat(edStyle.paddingRight) || 14;
        const top = paddingTop + lineIndex * lineHeight - ed.scrollTop;
        hl.style.height = lineHeight + 'px';
        hl.style.top = top + 'px';
        hl.style.left = paddingLeft + 'px';
        hl.style.right = paddingRight + 'px';
    }

    function toggle() {
        try {
            enabled = isEnabled();
            enabled = !enabled;
            localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off');
        } catch (e) { /* Tracking Prevention 등으로 storage 차단 시 in-memory만 유지 */ }
        updateUI();
        if (enabled) updateHighlight();
    }

    function saveColorOpts() {
        const colorEl = document.getElementById('hk-line-hl-color');
        const opacityEl = document.getElementById('hk-line-hl-opacity');
        const color = (colorEl && colorEl.value) ? colorEl.value : '#ffffff';
        const opacity = (opacityEl && opacityEl.value) ? parseInt(opacityEl.value, 10) : 15;
        try {
            localStorage.setItem(COLOR_KEY, JSON.stringify({ color, opacity }));
        } catch (e) {}
        applyColorOpts({ color, opacity: opacity / 100 });
        if (enabled) updateHighlight();
    }

    function loadToPanel() {
        const opts = loadColorOpts();
        const colorEl = document.getElementById('hk-line-hl-color');
        const opacityEl = document.getElementById('hk-line-hl-opacity');
        const opacityValEl = document.getElementById('hk-line-hl-opacity-val');
        if (colorEl) colorEl.value = opts.color;
        if (opacityEl) {
            opacityEl.value = Math.round(opts.opacity * 100);
            if (opacityValEl) opacityValEl.textContent = Math.round(opts.opacity * 100) + '%';
        }
        if (!_opacityBound) {
            _opacityBound = true;
            const r = document.getElementById('hk-line-hl-opacity');
            const v = document.getElementById('hk-line-hl-opacity-val');
            if (r && v) r.addEventListener('input', () => { v.textContent = r.value + '%'; });
        }
    }

    function init() {
        updateUI();
        const ed = document.getElementById('editor');
        const overrideEl = document.getElementById('hl-line-override');
        if (!ed) return;
        const run = () => { if (enabled) updateHighlight(); };
        ed.addEventListener('scroll', run, { passive: true });
        ed.addEventListener('click', run);
        ed.addEventListener('keyup', run);
        ed.addEventListener('input', run);
        document.addEventListener('selectionchange', () => { if (document.activeElement === ed) run(); });
        if (overrideEl) {
            overrideEl.addEventListener('input', run);
            overrideEl.addEventListener('change', run);
        }
        if (enabled) updateHighlight();
    }

    return { toggle, init, updateHighlight, isEnabled, updateUI, saveColorOpts, loadToPanel };
})();
