/* ═══════════════════════════════════════════════════════════
   커서 위치·선택 정보 및 포맷 버튼 상태 갱신
   의존: el (dom.js), 전역 App 없음 (DOM만 갱신)
   #cursor-pos: 마우스가 에디터 위에 있으면 마우스 줄, 아니면 캐럿 줄
═══════════════════════════════════════════════════════════ */
const CursorUI = {
    _mouseOverEditor: false,
    _lastMouseY: 0,
    updCursor() {
        const edi = el('editor');
        if (!edi) return;
        let line, col;
        if (this._mouseOverEditor) {
            line = getLineFromMouseY(edi, this._lastMouseY);
            col = 1;
        } else {
            const c = getCursorLineCol(edi);
            line = c.line;
            col = c.col;
        }
        const posEl = el('cursor-pos');
        if (posEl) posEl.textContent = `줄 ${line}, 열 ${col}`;
        const sl = edi.selectionEnd - edi.selectionStart;
        const selEl = el('sel-info');
        if (selEl) selEl.textContent = sl > 0 ? `${sl}자 선택` : '';
    },
    updFmtBtns() {
        const edi = el('editor');
        if (!edi) return;
        const s = edi.selectionStart, e = edi.selectionEnd;
        const b2 = edi.value.substring(s - 2, s), a2 = edi.value.substring(e, e + 2);
        const b3 = edi.value.substring(s - 3, s), a4 = edi.value.substring(e, e + 4);
        const boldBtn = el('bold-btn');
        if (boldBtn) boldBtn.classList.toggle('active', (b2 === '**' && a2 === '**') || (b3 === '<b>' && a4 === '</b>'));
        const b1 = edi.value.substring(s - 1, s), a1 = edi.value.substring(e, e + 1);
        const italicBtn = el('italic-btn');
        if (italicBtn) italicBtn.classList.toggle('active', b1 === '*' && a1 === '*');
    }
};
