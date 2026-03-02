/* ═══════════════════════════════════════════════════════════
   UNDO STACK (IndexedDB 저장 + 검증)
   의존: el (dom.js), 전역 TM/App (index.js 로드 후)
═══════════════════════════════════════════════════════════ */
const US = (() => {
    const MAX = 500;
    const DB_NAME = 'mdpro_undo_db';
    const STORE = 'undo';
    let st = [];
    let ptr = -1;
    let _persistTimer = null;

    function _currentTabId() {
        try { return (typeof TM !== 'undefined' && TM.getActive && TM.getActive()) ? TM.getActive().id : 'default'; } catch (e) { return 'default'; }
    }

    function _validEntry(e) {
        return e && typeof e.v === 'string' && Array.isArray(e.s) && e.s.length >= 2 && typeof e.s[0] === 'number' && typeof e.s[1] === 'number';
    }

    function _persist() {
        const id = _currentTabId();
        const payload = { stack: st.map(x => _validEntry(x) ? x : { v: '', s: [0, 0] }), ptr };
        try {
            const req = indexedDB.open(DB_NAME, 1);
            req.onupgradeneeded = () => { req.result.createObjectStore(STORE, { keyPath: 'id' }); };
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction(STORE, 'readwrite');
                const store = tx.objectStore(STORE);
                store.put({ id, ...payload });
                db.close();
            };
        } catch (err) { /* ignore */ }
    }

    function _schedulePersist() {
        if (_persistTimer) clearTimeout(_persistTimer);
        _persistTimer = setTimeout(() => { _persist(); _persistTimer = null; }, 100);
    }

    function push(v, s) {
        if (typeof v !== 'string' || !Array.isArray(s) || s.length < 2) return;
        st = st.slice(0, ptr + 1);
        st.push({ v, s: [s[0], s[1]] });
        if (st.length > MAX) st.shift();
        else ptr++;
        _schedulePersist();
    }

    const snap = () => {
        const e = el('editor');
        if (!e) return;
        push(e.value, [e.selectionStart, e.selectionEnd]);
    };

    function undo() {
        if (ptr <= 0) return;
        ptr--;
        const entry = st[ptr];
        if (!_validEntry(entry)) return;
        const ed = el('editor');
        if (!ed) return;
        ed.value = entry.v;
        ed.setSelectionRange(entry.s[0], entry.s[1]);
        if (typeof App !== 'undefined' && App.render) App.render();
        _schedulePersist();
    }

    function redo() {
        if (ptr >= st.length - 1) return;
        ptr++;
        const entry = st[ptr];
        if (!_validEntry(entry)) { ptr--; return; }
        const ed = el('editor');
        if (!ed) return;
        ed.value = entry.v;
        ed.setSelectionRange(entry.s[0], entry.s[1]);
        if (typeof App !== 'undefined' && App.render) App.render();
        _schedulePersist();
    }

    function _getState() {
        const stack = st.filter(_validEntry).map(e => ({ v: e.v, s: [e.s[0], e.s[1]] }));
        const p = Math.max(-1, Math.min(ptr, stack.length - 1));
        return { stack, ptr: p };
    }

    function _setState(newStack, newPtr) {
        const arr = Array.isArray(newStack) ? newStack : [];
        st = arr.filter(_validEntry).map(e => ({ v: String(e.v), s: [Number(e.s[0])||0, Number(e.s[1])||0] }));
        if (st.length === 0) st.push({ v: '', s: [0, 0] });
        ptr = typeof newPtr === 'number' && newPtr >= -1 && newPtr < st.length ? newPtr : st.length - 1;
        _schedulePersist();
    }

    return { snap, undo, redo, _getState, _setState };
})();
