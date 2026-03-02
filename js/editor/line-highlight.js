/* EditorLineHighlight — 에디터 현재 줄 하이라이트 (아주 투명한 현재 줄 표시) */
const EditorLineHighlight = (() => {
    const STORAGE_KEY = 'mdpro_editor_line_highlight';
    let enabled = true;

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return true; }
    }

    function updateUI() {
        enabled = isEnabled();
        const hl = document.getElementById('editor-line-highlight');
        const btn = document.getElementById('hk-line-highlight-btn');
        if (hl) hl.classList.toggle('vis', enabled);
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
    }

    function updateHighlight() {
        const hl = document.getElementById('editor-line-highlight');
        const ed = document.getElementById('editor');
        if (!hl || !ed || !enabled) return;
        const text = ed.value.substring(0, ed.selectionStart);
        const lineIndex = (text.match(/\n/g) || []).length;
        const style = window.getComputedStyle(ed);
        const lineHeight = parseFloat(style.lineHeight) || 21;
        const paddingTop = parseFloat(style.paddingTop) || 12;
        const paddingLeft = parseFloat(style.paddingLeft) || 14;
        const paddingRight = parseFloat(style.paddingRight) || 14;
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
        } catch (e) {}
        updateUI();
        if (enabled) updateHighlight();
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

    return { toggle, init, updateHighlight, isEnabled, updateUI };
})();
