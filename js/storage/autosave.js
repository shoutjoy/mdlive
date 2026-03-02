/* ═══════════════════════════════════════════════════════════
   AUTO SAVE — localStorage 자동 저장/복원 (에디터·제목)
   의존: el (dom.js)
═══════════════════════════════════════════════════════════ */
const AS = (() => {
    let t;
    const K = 'mdpro_v7';
    function load() {
        try {
            const d = JSON.parse(localStorage.getItem(K) || '{}');
            const ed = el('editor'), ti = el('doc-title');
            if (d.c && ed) ed.value = d.c;
            if (d.t && ti) ti.value = d.t;
        } catch (e) {}
    }
    function save(c, t2) {
        clearTimeout(t);
        const dot = el('save-dot'), st = el('save-st');
        if (dot) dot.classList.add('saving');
        if (st) st.textContent = '저장 중...';
        t = setTimeout(() => {
            try {
                localStorage.setItem(K, JSON.stringify({ c, t: t2, ts: Date.now() }));
                if (dot) { dot.classList.remove('saving'); dot.style.background = ''; }
                if (st) st.textContent = '저장됨';
            } catch (e) {
                if (dot) { dot.classList.remove('saving'); dot.style.background = '#f76a6a'; }
                if (st) st.textContent = '⚠ 자동저장 실패 (용량 초과) — 💾 저장 버튼으로 파일 저장 권장';
                console.warn('localStorage 저장 실패:', e);
            }
        }, 1000);
    }
    return { load, save };
})();
