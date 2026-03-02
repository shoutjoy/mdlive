/* ═══════════════════════════════════════════════════════════
   DOM / 공통 헬퍼 (전역 스코프 — index.js보다 먼저 로드)
═══════════════════════════════════════════════════════════ */
function el(id) { return document.getElementById(id); }

/** 현재 날짜·시간 문자열: "2026-02-27(금) 오전 12:04" */
function formatDateTime(d) {
    d = d || new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const weekdays = ['일', '월', '화', '수', '목', '금', '토'];
    const w = weekdays[d.getDay()];
    const h = d.getHours();
    const min = String(d.getMinutes()).padStart(2, '0');
    const ap = h < 12 ? '오전' : '오후';
    const h12 = h % 12 || 12;
    return `${y}-${m}-${day}(${w}) ${ap} ${h12}:${min}`;
}

function getCL(ed) {
    const pos = ed.selectionStart, bef = ed.value.substring(0, pos);
    const ls = bef.lastIndexOf('\n') + 1, aft = ed.value.substring(pos);
    const le = pos + (aft.indexOf('\n') === -1 ? aft.length : aft.indexOf('\n'));
    return { ls, le, text: ed.value.substring(ls, le) };
}

function dlBlob(content, filename, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = filename;
    a.click();
}
