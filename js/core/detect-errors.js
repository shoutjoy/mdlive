/* ═══════════════════════════════════════════════════════════
   ERROR DETECTION — 마크다운 표·코드블록 검사
   의존: 없음 (순수 함수)
   호출: Render.run(), App.showErrs() 에서 사용
═══════════════════════════════════════════════════════════ */
function detectErrors(md) {
    const errs = [];
    const lines = md.split('\n');
    function colCount(line) {
        const parts = line.split('|').map(c => c.trim());
        if (parts[0] === '' && parts[parts.length - 1] === '') return parts.length - 2;
        return parts.length;
    }
    lines.forEach((l, i) => {
        if (!l.startsWith('|')) return;
        const cols = colCount(l);
        if (i > 0 && lines[i - 1].startsWith('|')) {
            const prev = colCount(lines[i - 1]);
            if (prev !== cols && !l.includes('---') && !lines[i - 1].includes('---'))
                errs.push(`줄 ${i + 1}: 표 열 불일치 (이전 ${prev}, 현재 ${cols})`);
        }
    });
    if ((md.match(/^```/gm) || []).length % 2 !== 0) errs.push('코드 블록 미닫힘 (``` 누락)');
    return errs;
}
