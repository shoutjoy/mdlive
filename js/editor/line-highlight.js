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
        const wrap = document.getElementById('editor-line-highlight-wrap');
        const btn = document.getElementById('hk-line-highlight-btn');
        if (hl) hl.classList.toggle('vis', enabled);
        if (wrap) wrap.classList.toggle('vis', enabled);
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
        applyColorOpts(loadColorOpts());
    }

    function getDisplayLine() {
        const ed = document.getElementById('editor');
        if (!ed) return 1;
        let line;
        if (typeof CursorUI !== 'undefined' && CursorUI._mouseOverEditor) {
            line = getLineFromMouseY(ed, CursorUI._lastMouseY);
        } else {
            const c = getCursorLineCol(ed);
            line = c.line;
        }
        const totalLines = Math.max(1, (ed.value.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').length));
        return Math.max(1, Math.min(line, totalLines));
    }

    function updateHighlight() {
        const hl = document.getElementById('editor-line-highlight');
        const wrap = document.getElementById('editor-line-highlight-wrap');
        const track = document.getElementById('editor-line-highlight-track');
        const ed = document.getElementById('editor');
        if (!hl || !wrap || !track || !ed || !enabled) return;
        const line = getDisplayLine();
        const lineIndex = line - 1;
        /* 에디터 기준 lineHeight·padding — EZ 확대 시 드리프트 방지 */
        const edStyle = window.getComputedStyle(ed);
        const lineHeight = parseFloat(edStyle.lineHeight) || 21;
        const paddingTop = parseFloat(edStyle.paddingTop) || 12;
        const paddingLeft = parseFloat(edStyle.paddingLeft) || 14;
        const paddingRight = parseFloat(edStyle.paddingRight) || 14;
        /* 스크롤 동기화: wrap이 에디터와 같이 스크롤 → 35줄 이후에도 하이라이트 유지 */
        track.style.height = ed.scrollHeight + 'px';
        wrap.scrollTop = ed.scrollTop;
        wrap.scrollLeft = ed.scrollLeft;
        const top = paddingTop + lineIndex * lineHeight;
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
        if (!ed) return;
        const run = () => { if (enabled) updateHighlight(); };
        ed.addEventListener('scroll', run, { passive: true });
        ed.addEventListener('click', run);
        ed.addEventListener('keyup', run);
        ed.addEventListener('input', run);
        document.addEventListener('selectionchange', () => { if (document.activeElement === ed) run(); });
        if (enabled) updateHighlight();
    }

    return { toggle, init, updateHighlight, isEnabled, updateUI, saveColorOpts, loadToPanel };
})();
