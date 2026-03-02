/* ═══════════════════════════════════════════════════════════
   CORE EVENTS — 에디터/문서 이벤트 바인딩
   호출: App.init()에서 CoreEvents.init() 호출
   의존: el, App, US, TM, SS, LN, ED, PW, ScrollSync, handleKey (전역)
═══════════════════════════════════════════════════════════ */
const CoreEvents = {
    _pwCheckInterval: null,

    init() {
        const edi = el('editor');
        if (!edi) return;

        /* Ctrl+H: 찾기 — 캡처 단계 선점 */
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'h') {
                e.preventDefault();
                e.stopPropagation();
                App.toggleFind();
            }
        }, true);
        /* Ctrl+Alt+K: 다중선택 바 */
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.altKey && e.key && e.key.toLowerCase() === 'k') {
                if (edi && document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    e.preventDefault();
                    e.stopPropagation();
                    App.toggleMultiEditBar();
                }
            }
        }, true);
        /* Ctrl+Enter: 다중선택 적용 또는 다중선택 바 열기 */
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const meBar = el('multi-edit-bar');
                if (meBar && meBar.classList.contains('vis')) {
                    e.preventDefault();
                    App.multiEditApply();
                    return;
                }
                if (edi && document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    e.preventDefault();
                    App.toggleMultiEditBar();
                }
            }
        }, true);

        /* 한글 NFD 방지: 삽입 시 NFC 강제 */
        edi.addEventListener('beforeinput', (e) => {
            if (e.data != null && typeof e.data === 'string' && e.data.length > 0) {
                const nfcStr = e.data.normalize('NFC');
                if (nfcStr !== e.data) {
                    e.preventDefault();
                    const ss = edi.selectionStart, se = edi.selectionEnd;
                    edi.setRangeText(nfcStr, ss, se, 'end');
                }
            }
        }, true);
        edi.addEventListener('compositionend', () => {
            const v0 = edi.value;
            const v1 = v0.normalize('NFC');
            if (v0 === v1) return;
            const ss = edi.selectionStart, se = edi.selectionEnd;
            const leftCtx = v0.slice(Math.max(0, ss - 30), ss).normalize('NFC');
            edi.value = v1;
            const pos = v1.indexOf(leftCtx);
            const newStart = pos >= 0 ? pos + leftCtx.length : Math.min(ss, v1.length);
            edi.setSelectionRange(newStart, newStart);
            if (typeof US !== 'undefined' && US.snap) US.snap();
            if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
            if (typeof App !== 'undefined' && App.render) App.render();
        });
        edi.addEventListener('input', () => {
            US.snap();
            TM.markDirty();
            App.render();
            const findBar = el('find-bar'), fi = el('fi');
            if (findBar && findBar.classList.contains('vis') && fi && fi.value) {
                clearTimeout(App._findHighlightT);
                App._findHighlightT = setTimeout(() => App.updateFindHighlight(), 120);
            }
        });
        edi.addEventListener('keydown', typeof handleKey === 'function' ? handleKey : function() {});
        document.addEventListener('keydown', e => {
            if (document.activeElement !== edi) return;
            if (!e.altKey || e.ctrlKey || e.metaKey) return;
            if (e.code === 'Digit5') { e.preventDefault(); e.stopPropagation(); if (typeof ED !== 'undefined' && ED.textToList) ED.textToList(); }
            else if (e.code === 'Digit6') { e.preventDefault(); e.stopPropagation(); if (typeof ED !== 'undefined' && ED.textToNumberedList) ED.textToNumberedList(); }
        }, true);
        edi.addEventListener('keyup', () => { App.updCursor(); if (typeof SS !== 'undefined' && SS.onCursor) SS.onCursor(); });
        edi.addEventListener('click', () => { App.updCursor(); if (typeof SS !== 'undefined' && SS.onCursor) SS.onCursor(); });
        edi.addEventListener('mousemove', (e) => {
            CursorUI._mouseOverEditor = true;
            CursorUI._lastMouseY = e.clientY;
            App.updCursor();
            if (typeof EditorLineHighlight !== 'undefined' && EditorLineHighlight.isEnabled()) EditorLineHighlight.updateHighlight();
        });
        edi.addEventListener('mouseleave', () => {
            CursorUI._mouseOverEditor = false;
            App.updCursor();
            if (typeof EditorLineHighlight !== 'undefined' && EditorLineHighlight.isEnabled()) EditorLineHighlight.updateHighlight();
        });
        edi.addEventListener('scroll', () => {
            if (typeof LN !== 'undefined' && LN.update) LN.update();
            if (typeof ScrollSync !== 'undefined' && ScrollSync.onEditor) ScrollSync.onEditor();
            const hl = document.getElementById('editor-find-highlight');
            if (hl && hl.style.display === 'block') { hl.scrollTop = edi.scrollTop; hl.scrollLeft = edi.scrollLeft; }
        }, { passive: true });
        document.addEventListener('selectionchange', () => {
            if (document.activeElement === edi) {
                App.updCursor();
                App.updFmtBtns();
                if (typeof EditorLineHighlight !== 'undefined' && EditorLineHighlight.isEnabled()) EditorLineHighlight.updateHighlight();
            }
        });
        document.addEventListener('keydown', e => { if (document.activeElement !== edi && typeof handleKey === 'function') handleKey(e); });

        const fiEl = document.getElementById('fi');
        if (fiEl) fiEl.addEventListener('input', () => { App._findStart = undefined; App.updateFindHighlight(); });
        const docTitle = el('doc-title');
        if (docTitle) docTitle.addEventListener('input', () => { TM.markDirty(); App.render(); });

        if (this._pwCheckInterval) clearInterval(this._pwCheckInterval);
        this._pwCheckInterval = setInterval(() => { if (typeof PW !== 'undefined' && PW.checkClosed) PW.checkClosed(); }, 2000);
    }
};
