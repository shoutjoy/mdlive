/* ═══════════════════════════════════════════════════════════
   Debounce 유틸 (점진적 적용용)
   사용: debounce(fn, ms) → 연속 호출 시 마지막만 ms 후 실행
═══════════════════════════════════════════════════════════ */
function debounce(fn, ms) {
    let t = null;
    return function (...args) {
        if (t) clearTimeout(t);
        t = setTimeout(() => { fn.apply(this, args); t = null; }, ms);
    };
}
