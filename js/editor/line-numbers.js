/* ═══════════════════════════════════════════════════════════
   LINE NUMBERS — 에디터 왼쪽 줄번호
   의존: el (dom.js)
═══════════════════════════════════════════════════════════ */
const LN = (() => {
    let v = true;
    function update() {
        if (!v) return;
        const ed = el('editor'), c = el('lnc');
        if (!ed || !c) return;
        c.innerHTML = ed.value.split('\n').map((_, i) => `<div class="ln">${i + 1}</div>`).join('');
        const lineNumbers = el('line-numbers');
        if (lineNumbers) lineNumbers.scrollTop = ed.scrollTop;
    }
    function toggle() {
        v = !v;
        const ln = el('line-numbers'), ed = el('editor'), btn = el('ln-btn');
        if (ln) ln.classList.toggle('vis', v);
        if (ed) ed.classList.toggle('wln', v);
        if (btn) btn.classList.toggle('active', v);
        update();
    }
    function init() {
        const ln = el('line-numbers'), ed = el('editor'), btn = el('ln-btn');
        if (ln) ln.classList.toggle('vis', v);
        if (ed) ed.classList.toggle('wln', v);
        if (btn) btn.classList.toggle('active', v);
        update();
    }
    return { update, toggle, init };
})();
