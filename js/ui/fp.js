/* FP — Format Quick Panel (Alt+L) → js/ui/fp.js
   의존: el, ins (전역) */

/* ═══════════════════════════════════════════════════════════
   FORMAT QUICK PANEL (Alt+L)
═══════════════════════════════════════════════════════════ */
const FP = (() => {
    let vis = false;
    function show() {
        const panel = el('fmt-panel');
        if (vis) { hide(); return }
        const tb = document.querySelector('#toolbar');
        const rect = tb.getBoundingClientRect();
        panel.style.left = '50%'; panel.style.top = (rect.bottom + 4) + 'px';
        panel.style.transform = 'translateX(-50%)';
        panel.classList.add('vis'); vis = true;
        setTimeout(() => document.addEventListener('click', _outside, { once: true }), 10);
    }
    function hide() { el('fmt-panel').classList.remove('vis'); vis = false }
    function _outside(e) { if (!el('fmt-panel').contains(e.target)) hide(); else setTimeout(() => document.addEventListener('click', _outside, { once: true }), 10) }

    function fsz(dir) {
        const sel = el('fp-fsize');
        const idx = sel.selectedIndex;
        const ni = Math.max(0, Math.min(sel.options.length - 1, idx + dir));
        sel.selectedIndex = ni; applyFsize();
    }
    function applyFsize() {
        const size = el('fp-fsize').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="font-size:${size}">${sel2}</span>`);
    }
    function setFc(c) { el('fp-fc').value = c === '#e8e8f0' ? '#e8e8f0' : c; applyColor() }
    function applyColor() {
        const c = el('fp-fc').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="color:${c}">${sel2}</span>`);
    }
    function setHL(c) { if (c === 'none') { applyHLnone(); return } el('fp-hl').value = c; applyHL() }
    function applyHL() {
        const c = el('fp-hl').value;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e) || '텍스트';
        ins(ed, s, e, `<span style="background:${c}">${sel2}</span>`);
    }
    function applyHLnone() {
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd;
        const sel2 = ed.value.substring(s, e);
        if (sel2) ins(ed, s, e, sel2.replace(/<span style="background:[^"]*">(.*?)<\/span>/gs, '$1'));
    }
    return { show, hide, fsz, applyFsize, setFc, applyColor, setHL, applyHL };
})();
