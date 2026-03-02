/* EZ — 에디터 글자 크기 확대/축소 (el, EditorLineHighlight 의존) */
/* ═══════════════════════════════════════════════════════════
   EZ — 에디터 입력창 글자 크기 확대/축소 (Ctrl+0/Ctrl+9)
═══════════════════════════════════════════════════════════ */
const EZ = (() => {
    const SIZES = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 22, 24];
    const LHMAP = [14, 15, 16, 18, 19, 21, 22, 24, 26, 28, 30, 33, 36];
    let idx = 3; /* 기본 12px */

    function _apply() {
        const ed = el('editor');
        if (!ed) return;
        const sz = SIZES[idx];
        const lh = LHMAP[idx];
        ed.style.fontSize  = sz + 'px';
        ed.style.lineHeight = lh + 'px';
        const lbl = el('ez-lbl');
        if (lbl) lbl.textContent = sz + 'px';
        /* 라인 넘버 높이도 동기화 */
        const lnc = el('lnc');
        if (lnc) lnc.style.lineHeight = lh + 'px';
        /* 저장 */
        try { localStorage.setItem('mdpro_ez_idx', idx); } catch(e) {}
        if (typeof EditorLineHighlight !== 'undefined' && EditorLineHighlight.isEnabled()) EditorLineHighlight.updateHighlight();
    }

    function inc() { if (idx < SIZES.length - 1) { idx++; _apply(); } }
    function dec() { if (idx > 0) { idx--; _apply(); } }

    function init() {
        try {
            const saved = parseInt(localStorage.getItem('mdpro_ez_idx'));
            if (!isNaN(saved) && saved >= 0 && saved < SIZES.length) idx = saved;
        } catch(e) {}
        _apply();
    }

    return { inc, dec, init };
})();
