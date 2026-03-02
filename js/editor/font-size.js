/* ═══════════════════════════════════════════════════════════
   FONT SIZE MANAGER — 선택 텍스트에 글자 크기 적용
   의존: el (dom.js), ins (index.js — 런타임)
═══════════════════════════════════════════════════════════ */
const FS = (() => {
    const SIZES = [8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 36, 40, 48, 50];
    let cur = 4;

    function updateDisplay() {
        const disp = el('fsize-display');
        if (disp) disp.textContent = SIZES[cur] + 'pt';
    }

    function apply() {
        const pt = SIZES[cur];
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const sel = ed.value.substring(s, e) || '텍스트';
        if (typeof ins === 'function') ins(ed, s, e, `<span style="font-size:${pt}pt">${sel}</span>`);
        else { ed.setRangeText(`<span style="font-size:${pt}pt">${sel}</span>`, s, e, 'end'); }
    }

    function inc() { if (cur < SIZES.length - 1) { cur++; updateDisplay(); apply(); } }
    function dec() { if (cur > 0) { cur--; updateDisplay(); apply(); } }

    let _picker = null;
    function clickPick(ev) {
        ev.stopPropagation();
        if (_picker) { _picker.remove(); _picker = null; return; }
        const rect = el('fsize-display').getBoundingClientRect();
        const div = document.createElement('div');
        div.style.cssText = `position:fixed;left:${rect.left}px;top:${rect.bottom + 2}px;background:var(--bg2);border:1px solid var(--bd);border-radius:6px;box-shadow:0 6px 24px rgba(0,0,0,.4);z-index:9999;overflow:hidden;min-width:70px`;
        div.innerHTML = SIZES.map((s, i) => `<div data-i="${i}" style="padding:5px 14px;font-family:var(--fm);font-size:12px;cursor:pointer;color:${i === cur ? 'var(--ac)' : 'var(--tx)'};background:${i === cur ? 'var(--acg)' : 'transparent'};transition:background .1s" onmouseenter="this.style.background='var(--bg5)'" onmouseleave="this.style.background='${i === cur ? 'var(--acg)' : 'transparent'}'" onclick="FS.pickSize(${i},event)">${s}pt</div>`).join('');
        document.body.appendChild(div);
        _picker = div;
        setTimeout(() => document.addEventListener('click', _closePicker, { once: true }), 10);
    }
    function _closePicker() { if (_picker) { _picker.remove(); _picker = null; } }
    function pickSize(i, ev) { if (ev) ev.stopPropagation(); cur = i; updateDisplay(); _closePicker(); apply(); }

    function startEdit(ev) {
        ev.stopPropagation(); _closePicker();
        const disp = el('fsize-display'), inp = el('fsize-input');
        if (inp) inp.value = SIZES[cur];
        if (disp) disp.style.display = 'none';
        if (inp) { inp.style.display = 'inline-block'; inp.focus(); inp.select(); }
    }
    function endEdit() {
        const inp = el('fsize-input'), disp = el('fsize-display');
        const v = parseInt(inp.value, 10);
        if (v >= 6 && v <= 200) {
            let best = 0, bDiff = 999;
            SIZES.forEach((s, i) => { const d = Math.abs(s - v); if (d < bDiff) { bDiff = d; best = i; } });
            cur = best; updateDisplay(); apply();
        }
        if (inp) inp.style.display = 'none';
        if (disp) disp.style.display = '';
    }
    function editKey(ev) {
        if (ev.key === 'Enter') { const i = el('fsize-input'); if (i) i.blur(); }
        if (ev.key === 'Escape') { const i = el('fsize-input'); const d = el('fsize-display'); if (i) i.style.display = 'none'; if (d) d.style.display = ''; }
    }

    function update() { updateDisplay(); }
    return { inc, dec, update, clickPick, pickSize, startEdit, endEdit, editKey };
})();
