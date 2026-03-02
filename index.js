/* ins, repCL: App/US 의존 — index.js에 유지 */
function ins(ed, s, e, text) { ed.value = ed.value.substring(0, s) + text + ed.value.substring(e); const p = s + text.length; ed.setSelectionRange(p, p); ed.focus(); App.render(); US.snap() }
function repCL(ed, t) { const { ls, le } = getCL(ed); ed.value = ed.value.substring(0, ls) + t + ed.value.substring(le); const p = ls + t.length; ed.setSelectionRange(p, p); ed.focus(); App.render(); US.snap() }

/* AppLock → js/core/app-lock.js */

/* AiApiKey → js/core/ai-apikey.js */

/* ScholarApiKey → js/core/scholar-apikey.js */

/* mdRender, splitPages, parseSlideContent, parseMarkdownToSlides → js/markdown/parser.js */

/* PR (Preview Renderer) → js/markdown/preview.js */

/* SlideMode → js/markdown/slide-mode.js */

/* PV → js/markdown/pv.js */

/* IPPT → js/editor/ippt.js */

/* A4Ruler → js/markdown/a4-ruler.js */


/* CP — 미리보기 복사 매니저: 추후 분리 또는 인라인 유지 */
const CP = (() => {
    function getPageNodes() {
        const c = el('preview-container');
        if (!c) return [];
        if (c.classList.contains('slide-mode')) return [...c.querySelectorAll('.ppt-slide .slide-inner')];
        return [...c.querySelectorAll('.preview-page')];
    }
    function buildHtml(nodes) {
        const parts = nodes.map(n => {
            const clone = n.cloneNode(true);
            return clone.innerHTML;
        });
        const body = parts.join('\n<hr style="border:none;border-top:1px dashed #ccc;margin:18px 0">\n');
        return `<div style="font-family:serif;font-size:11pt;line-height:1.8;color:#1a1a2e;max-width:170mm;word-break:break-word">${body}</div>`;
    }
    function flash(btnId, successLabel, color) {
        const btn = el(btnId);
        if (!btn) return;
        const orig = btn.textContent;
        const origColor = btn.style.color;
        btn.textContent = successLabel;
        btn.style.color = color || '#6af7a0';
        btn.style.opacity = '0.7';
        setTimeout(() => {
            btn.textContent = orig;
            btn.style.color = origColor;
            btn.style.opacity = '';
        }, 1600);
    }
    return {
        async copyRich() {
            const nodes = getPageNodes();
            if (!nodes.length) { alert('미리보기 내용이 없습니다.'); return; }
            const htmlStr = buildHtml(nodes);
            const textStr = nodes.map(n => n.innerText).join('\n\n');
            try {
                if (window.ClipboardItem) {
                    const htmlBlob = new Blob([htmlStr], { type: 'text/html' });
                    const textBlob = new Blob([textStr], { type: 'text/plain' });
                    await navigator.clipboard.write([new ClipboardItem({ 'text/html': htmlBlob, 'text/plain': textBlob })]);
                } else {
                    const tmp = document.createElement('div');
                    tmp.innerHTML = htmlStr;
                    tmp.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
                    document.body.appendChild(tmp);
                    const range = document.createRange();
                    range.selectNodeContents(tmp);
                    const sel = window.getSelection();
                    sel.removeAllRanges();
                    sel.addRange(range);
                    document.execCommand('copy');
                    sel.removeAllRanges();
                    document.body.removeChild(tmp);
                }
                flash('copy-rich-btn', '✓ 복사됨', '#6af7a0');
            } catch (err) {
                try {
                    await navigator.clipboard.writeText(textStr);
                    flash('copy-rich-btn', '✓ 텍스트로 복사', '#f7d06a');
                } catch (e2) {
                    alert('클립보드 복사에 실패했습니다.\n브라우저 주소창을 한 번 클릭한 뒤 다시 시도해 주세요.');
                }
            }
        },
        async copyText() {
            const nodes = getPageNodes();
            if (!nodes.length) { alert('미리보기 내용이 없습니다.'); return; }
            const text = nodes.map(n => n.innerText.trim()).join('\n\n');
            try {
                await navigator.clipboard.writeText(text);
                flash('copy-text-btn', '✓ 복사됨', '#6af7a0');
            } catch (err) {
                alert('클립보드 복사에 실패했습니다.');
            }
        },
    };
})();

/* PW → js/core/pw.js */

/* SS → js/editor/scroll-sync.js */

/* ═══════════════════════════════════════════════════════════
   TM — Tab Manager (멀티파일 탭 편집)
   각 탭은 독립적인 content, title, undo stack을 가진다.
   localStorage key: 'mdpro_tabs_v1' (탭 목록 + 내용 영속)
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   TM — Tab Manager  (멀티파일 탭 편집)
   ─ 탭별 독립 content / undo stack / dirty flag
   ─ localStorage 'mdpro_tabs_v1' 에 전체 세션 영속
   ─ 구버전 'mdpro_v7' 자동 마이그레이션
═══════════════════════════════════════════════════════════ */
/* TM → js/core/tm.js */

/* ═══════════════════════════════════════════════════════════
   CITATION MANAGER
═══════════════════════════════════════════════════════════ */
/* SB → js/core/sb.js */

/* CiteModal → js/ui/cite-modal.js */

/* CiteAISearch → js/cite/cite-ai-search.js */

/* CiteAiSearchHistory → js/cite/cite-ai-history.js */

/* CAP (Caption Manager) → js/cite/cap.js */

/* TMPLS → js/data/templates.js (로드 시 전역 TMPLS 사용) */

/* Scholar → js/scholar/scholar.js */

/* AiPPT → js/ai/ai-ppt.js */

/* RefSearch → js/cite/ref-search.js */

/* ColorPicker → js/utils/color-picker.js */

/* ═══════════════════════════════════════════════════════════
   EDITOR ACTIONS
═══════════════════════════════════════════════════════════ */
/* IMG, _showImgpv, ImgCrop, ImgInsert, initImgUrlPreview → js/image/img.js */

/* ImgStore → js/image/img-store.js */

/* AiImage -> js/image/ai-image.js */

/* PvImageResize → js/image/pv-image-resize.js (PV 이미지 마우스 resize) */

const ED = {
    ed() { return el('editor') },
    h(lv) { const ed = this.ed(); repCL(ed, '#'.repeat(lv) + ' ' + getCL(ed).text.replace(/^#+\s*/, '')) },
    bold() {
        const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e);
        if (!sel) { ins(ed, s, e, '**텍스트**'); ed.setSelectionRange(s + 2, s + 5); return }
        const b2 = ed.value.substring(s - 2, s), a2 = ed.value.substring(e, e + 2);
        if (b2 === '**' && a2 === '**') { ed.value = ed.value.substring(0, s - 2) + sel + ed.value.substring(e + 2); ed.setSelectionRange(s - 2, e - 2); App.render(); US.snap(); return }
        const b3 = ed.value.substring(s - 3, s), a4 = ed.value.substring(e, e + 4);
        if (b3 === '<b>' && a4 === '</b>') { ed.value = ed.value.substring(0, s - 3) + sel + ed.value.substring(e + 4); ed.setSelectionRange(s - 3, e - 3); App.render(); US.snap(); return }
        const w = /[()[\]{}<>]/.test(sel) ? `<b>${sel}</b>` : `**${sel}**`;
        ins(ed, s, e, w); ed.setSelectionRange(s, s + w.length);
    },
    italic() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e) || '텍스트'; const b = ed.value.substring(s - 1, s), a = ed.value.substring(e, e + 1); if (b === '*' && a === '*') { ed.value = ed.value.substring(0, s - 1) + sel + ed.value.substring(e + 1); ed.setSelectionRange(s - 1, s - 1 + sel.length); App.render() } else ins(ed, s, e, `*${sel}*`) },
    strike() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd; ins(ed, s, e, `~~${ed.value.substring(s, e) || '텍스트'}~~`) },
    inlineCode() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd; ins(ed, s, e, `\`${ed.value.substring(s, e) || 'code'}\``) },
    fontSize(size) { if (!size) return; const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e) || '텍스트'; ins(ed, s, e, `<span style="font-size:${size}">${sel}</span>`) },
    align(dir) { const ed = this.ed(); const { text } = getCL(ed); const c = text.replace(/<div[^>]*>(.*?)<\/div>/gi, '$1'); repCL(ed, dir === 'left' ? c : `<div style="text-align:${dir}">${c}</div>`) },
    textToList() {
        const ed = this.ed();
        if (!ed) return;
        const val = ed.value;
        const ss  = ed.selectionStart;
        const se  = ed.selectionEnd;
        if (ss === se) {
            /* 선택 없음 → 현재 줄 토글 */
            const ls = val.lastIndexOf('\n', ss - 1) + 1;
            const nlPos = val.indexOf('\n', ls);
            const lineEnd = nlPos === -1 ? val.length : nlPos;
            const line = val.slice(ls, lineEnd);
            if (line.match(/^[-*+]\s/) || line.match(/^\d+\.\s/)) {
                ed.setRangeText(line.replace(/^([-*+]\s|\d+\.\s)/, ''), ls, lineEnd, 'start');
            } else {
                ed.setRangeText('- ', ls, ls, 'start');
            }
        } else {
            /* 선택 있음 → 선택한 텍스트 전체를 줄 단위로 나누어 각 줄에 "- " 토글 */
            const block = val.substring(ss, se);
            const lines = block.split('\n');
            const allList = lines.every(l => l.match(/^[-*+]\s/) || l.match(/^\d+\.\s/) || l.trim() === '');
            const newBlock = allList
                ? lines.map(l => l.replace(/^([-*+]\s|\d+\.\s)/, '')).join('\n')
                : lines.map(l => l.trim() === '' ? l : (l.match(/^[-*+]\s/) || l.match(/^\d+\.\s/) ? l : '- ' + l)).join('\n');
            ed.setRangeText(newBlock, ss, se, 'select');
        }
        US.snap(); TM.markDirty(); App.render();
    },
    textToNumberedList() {
        const ed = this.ed();
        if (!ed) return;
        const val = ed.value;
        const ss = ed.selectionStart;
        const se = ed.selectionEnd;
        if (ss === se) {
            const ls = val.lastIndexOf('\n', ss - 1) + 1;
            const nlPos = val.indexOf('\n', ls);
            const lineEnd = nlPos === -1 ? val.length : nlPos;
            const line = val.slice(ls, lineEnd);
            if (line.match(/^\d+\.\s/)) {
                ed.setRangeText(line.replace(/^\d+\.\s/, ''), ls, lineEnd, 'start');
            } else {
                ed.setRangeText('1. ', ls, ls, 'start');
            }
        } else {
            const block = val.substring(ss, se);
            const lines = block.split('\n');
            const allNumbered = lines.every(l => l.match(/^\d+\.\s/) || l.trim() === '');
            const newBlock = allNumbered
                ? lines.map(l => l.replace(/^\d+\.\s/, '')).join('\n')
                : lines.map((l, i) => l.trim() === '' ? l : (l.match(/^\d+\.\s/) ? l : (i + 1) + '. ' + l)).join('\n');
            ed.setRangeText(newBlock, ss, se, 'select');
        }
        US.snap(); TM.markDirty(); App.render();
    },
        list(type) { const ed = this.ed(), s = ed.selectionStart; const p = type === 'ul' ? '- ' : '1. '; ins(ed, s, s, `\n${p}항목 1\n${p}항목 2\n${p}항목 3\n`) },
    bquote() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e); if (sel) ins(ed, s, e, sel.split('\n').map(l => '> ' + l).join('\n')); else ins(ed, s, s, '\n> 인용문을 입력하세요\n') },
    table() { const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, '\n| 헤더 1 | 헤더 2 | 헤더 3 |\n| :-- | :-- | :-- |\n| 셀 | 셀 | 셀 |\n| 셀 | 셀 | 셀 |\n') },
    tableRow() { const ed = this.ed(), val = ed.value, pos = ed.selectionStart; const le = val.indexOf('\n', pos), ln = val.substring(val.lastIndexOf('\n', pos - 1) + 1, le === -1 ? val.length : le); if (!ln.trim().startsWith('|')) { this.table(); return } const cols = ln.split('|').filter(c => c.trim() !== '').length; ins(ed, le === -1 ? val.length : le, le === -1 ? val.length : le, '\n|' + ' 셀 |'.repeat(cols)) },
    tableCol() { const ed = this.ed(), lines = ed.value.split('\n'); const cur = ed.value.substring(0, ed.selectionStart).split('\n').length - 1; if (!lines[cur].trim().startsWith('|')) { this.table(); return } let s = cur, e2 = cur; while (s > 0 && lines[s - 1].trim().startsWith('|')) s--; while (e2 < lines.length - 1 && lines[e2 + 1].trim().startsWith('|')) e2++; ed.value = lines.map((l, i) => { if (i < s || i > e2 || !l.trim().startsWith('|')) return l; return /^\|[\s:|-]+\|$/.test(l.trim()) ? l.trimEnd() + ' :-- |' : l.trimEnd() + ' 새열 |' }).join('\n'); App.render(); US.snap() },

    /* ── 셀 병합 시스템 (MD 표 + HTML 표 모두 지원, 반복 병합 가능) ── */

    _getMdTable(ed) {
        const lines = ed.value.split('\n');
        const cur = ed.value.substring(0, ed.selectionStart).split('\n').length - 1;
        if (!lines[cur].trim().startsWith('|')) return null;
        let s = cur, e2 = cur;
        while (s > 0 && lines[s - 1].trim().startsWith('|')) s--;
        while (e2 < lines.length - 1 && lines[e2 + 1].trim().startsWith('|')) e2++;
        let sepIdx = -1;
        for (let i = s; i <= e2; i++) { if (/^\|[\s:|-]+\|$/.test(lines[i].trim())) { sepIdx = i; break; } }
        return { lines, start: s, end: e2, cur, sep: sepIdx };
    },

    _parseCells(line) {
        return line.split('|').slice(1, -1).map(c => c.trim());
    },

    _getCursorCell(ed) {
        const val = ed.value, pos = ed.selectionStart;
        const ls = val.lastIndexOf('\n', pos - 1) + 1;
        const part = val.substring(ls, pos);
        return Math.max(0, part.split('|').length - 2);
    },

    /* HTML 표 파싱: DOMParser로 기존 colspan/rowspan 유지하며 재파싱 */
    _getHTMLTable(ed) {
        const val = ed.value, pos = ed.selectionStart;
        const before = val.substring(0, pos);
        const tStart = before.lastIndexOf('<table');
        if (tStart === -1) return null;
        const tEnd = val.indexOf('</table>', tStart);
        if (tEnd === -1) return null;
        const tableHTML = val.substring(tStart, tEnd + 8);
        const doc = new DOMParser().parseFromString('<body>' + tableHTML + '</body>', 'text/html');
        const table = doc.querySelector('table');
        if (!table) return null;
        const trs = [...table.querySelectorAll('tr')];
        if (!trs.length) return null;
        // 최대 열 수 계산
        const cols = trs.reduce((mx, tr) => {
            let n = 0;[...tr.cells].forEach(c => n += c.colSpan || 1); return Math.max(mx, n);
        }, 0);
        const rows = trs.length;
        // cells[r][c] = {text,cs,rs,skip}
        const cells = Array.from({ length: rows }, () => Array(cols).fill(null));
        const occupied = Array.from({ length: rows }, () => Array(cols).fill(false));
        trs.forEach((tr, r) => {
            let gc = 0;
            [...tr.cells].forEach(td => {
                while (gc < cols && occupied[r][gc]) gc++;
                const cs = td.colSpan || 1, rs = td.rowSpan || 1;
                cells[r][gc] = { text: td.innerHTML.trim(), cs, rs, skip: false };
                for (let dr = 0; dr < rs; dr++)for (let dc = 0; dc < cs; dc++) {
                    if (r + dr < rows && gc + dc < cols) {
                        occupied[r + dr][gc + dc] = true;
                        if (dr > 0 || dc > 0) cells[r + dr][gc + dc] = { text: '', cs: 1, rs: 1, skip: true };
                    }
                }
                gc += cs;
            });
        });
        // 빈 셀 보정
        for (let r = 0; r < rows; r++)for (let c = 0; c < cols; c++) {
            if (!cells[r][c]) cells[r][c] = { text: '', cs: 1, rs: 1, skip: false };
        }
        // 커서 위치 → rowIdx, curCol 계산
        const posInTable = pos - tStart;
        const sliced = tableHTML.substring(0, posInTable);
        const rowIdx = Math.max(0, (sliced.match(/<tr[\s>]/gi) || []).length - 1);
        const tdIdx = Math.max(0, (sliced.match(/<t[dh][\s>]/gi) || []).length - 1);
        // tdIdx번째 실제 td/th가 그리드의 몇 번 열인지
        let gc2 = 0, counted = 0, curCol = 0;
        if (trs[rowIdx]) {
            for (const td of trs[rowIdx].cells) {
                while (gc2 < cols && occupied[rowIdx] && rowIdx > 0 && cells[rowIdx][gc2]?.skip) gc2++;
                if (counted === tdIdx) { curCol = gc2; break; }
                gc2 += td.colSpan || 1; counted++;
            }
        }

        return { cells, rows, cols, rowIdx, curCol, tStart, tEnd: tEnd + 8, val };
    },

    _renderHTMLTable(cells, rows, cols) {
        let html = '\n<table>\n<thead>\n<tr>';
        for (let c = 0; c < cols; c++) {
            const cell = cells[0]?.[c]; if (!cell || cell.skip) continue;
            const cs = cell.cs > 1 ? ` colspan="${cell.cs}"` : ''
            const rs = cell.rs > 1 ? ` rowspan="${cell.rs}"` : ''
            html += `<th${cs}${rs}>${cell.text}</th>`;
        }
        html += '</tr>\n</thead>\n<tbody>';
        for (let r = 1; r < rows; r++) {
            html += '\n<tr>';
            for (let c = 0; c < cols; c++) {
                const cell = cells[r]?.[c]; if (!cell || cell.skip) continue;
                const cs = cell.cs > 1 ? ` colspan="${cell.cs}"` : ''
                const rs = cell.rs > 1 ? ` rowspan="${cell.rs}"` : ''
                html += `<td${cs}${rs}>${cell.text}</td>`;
            }
            html += '</tr>';
        }
        html += '\n</tbody>\n</table>\n';
        return html;
    },

    /* 공통 병합 실행: MD 표 → HTML 변환, HTML 표 → 직접 파싱 후 재병합 */
    _doMerge(dir) {
        const ed = this.ed();
        // ① HTML 표 우선 시도
        const htbl = this._getHTMLTable(ed);
        if (htbl) {
            const { cells, rows, cols, rowIdx, curCol, tStart, tEnd, val } = htbl;
            const cell = cells[rowIdx]?.[curCol];
            if (!cell || cell.skip) { alert('이미 병합된 셀이거나 유효하지 않은 위치입니다.\n셀 텍스트 위에 커서를 놓고 실행하세요.'); return; }
            if (dir === 'h') {
                const nc = curCol + cell.cs;
                if (nc >= cols) { alert('오른쪽에 병합할 셀이 없습니다.'); return; }
                const right = cells[rowIdx][nc];
                if (!right || right.skip) { alert('오른쪽 셀이 이미 병합 중입니다.'); return; }
                cell.text = (cell.text + (right.text ? ' ' + right.text : '')).trim();
                cell.cs += right.cs;
                for (let cc = curCol + 1; cc < curCol + cell.cs; cc++)if (cells[rowIdx][cc]) cells[rowIdx][cc].skip = true;
            } else {
                const nr = rowIdx + cell.rs;
                if (nr >= rows) { alert('아래에 병합할 셀이 없습니다.'); return; }
                const below = cells[nr]?.[curCol];
                if (!below || below.skip) { alert('아래 셀이 이미 병합 중입니다.'); return; }
                cell.text = (cell.text + (below.text ? ' ' + below.text : '')).trim();
                cell.rs += below.rs;
                for (let rr = rowIdx + 1; rr < rowIdx + cell.rs; rr++)if (cells[rr]?.[curCol]) cells[rr][curCol].skip = true;
            }
            const newHTML = this._renderHTMLTable(cells, rows, cols);
            ed.value = val.substring(0, tStart) + newHTML + val.substring(tEnd);
            App.render(); US.snap();
            return;
        }
        // ② Markdown 표 처리
        const tbl = this._getMdTable(ed);
        if (!tbl) { alert('커서를 표 안에 놓고 실행하세요.'); return; }
        const { lines, start, end, cur, sep } = tbl;
        const col = this._getCursorCell(ed);
        const allRows = [];
        for (let i = start; i <= end; i++) { if (i !== sep) allRows.push(this._parseCells(lines[i])); }
        if (allRows.length < 2) return;
        const cols2 = allRows[0].length;
        const cells2 = allRows.map(row => row.map(t => ({ text: t || '', cs: 1, rs: 1, skip: false })));
        const dataLines = [];
        for (let i = start; i <= end; i++) { if (i !== sep) dataLines.push(i); }
        const rowIdx2 = dataLines.indexOf(cur);
        if (rowIdx2 < 0) { alert('커서를 표 셀 안에 놓고 실행하세요.'); return; }
        if (dir === 'h') {
            if (col >= cols2 - 1) { alert('오른쪽에 병합할 셀이 없습니다.'); return; }
            const c1 = cells2[rowIdx2][col], c2 = cells2[rowIdx2][col + 1];
            c1.text = (c1.text + (c2.text ? ' ' + c2.text : '')).trim(); c1.cs = 2; c2.skip = true;
        } else {
            if (rowIdx2 >= allRows.length - 1) { alert('아래에 병합할 셀이 없습니다.'); return; }
            const c1 = cells2[rowIdx2][col], c2 = cells2[rowIdx2 + 1][col];
            c1.text = (c1.text + (c2.text ? ' ' + c2.text : '')).trim(); c1.rs = 2; c2.skip = true;
        }
        const bef = lines.slice(0, start).join('\n');
        const aft = lines.slice(end + 1).join('\n');
        ed.value = (bef ? (bef + '\n') : '') + this._renderHTMLTable(cells2, allRows.length, cols2) + (aft ? ('\n' + aft) : '');
        App.render(); US.snap();
    },

    mergeH() { this._doMerge('h'); },
    mergeV() { this._doMerge('v'); },

    /* HTML 표를 들여쓰기가 잘 된 형태로 정돈 */
    tidyTable() {
        const ed = this.ed();
        const htbl = this._getHTMLTable(ed);
        if (!htbl) { alert('커서를 HTML 표 안에 놓고 Tidy를 실행하세요.\n(병합이 있는 HTML 표에서 사용합니다.)'); return; }
        const { cells, rows, cols, tStart, tEnd, val } = htbl;

        // 들여쓰기 정돈된 HTML 생성
        function tidyCell(tag, cell, indent) {
            const attrs = [];
            if (cell.rs > 1) attrs.push(`rowspan="${cell.rs}"`);
            if (cell.cs > 1) attrs.push(`colspan="${cell.cs}"`);
            const attrStr = attrs.length ? ' ' + attrs.join(' ') : '';
            return `${indent}<${tag}${attrStr}>${cell.text}</${tag}>`;
        }

        const lines = [];
        lines.push('<table>');

        // thead: 첫 번째 행
        lines.push('  <thead>');
        lines.push('    <tr>');
        for (let c = 0; c < cols; c++) {
            const cell = cells[0]?.[c];
            if (!cell || cell.skip) continue;
            lines.push(tidyCell('th', cell, '      '));
        }
        lines.push('    </tr>');
        lines.push('  </thead>');

        // tbody: 나머지 행
        lines.push('  <tbody>');
        for (let r = 1; r < rows; r++) {
            lines.push('    <tr>');
            for (let c = 0; c < cols; c++) {
                const cell = cells[r]?.[c];
                if (!cell || cell.skip) continue;
                lines.push(tidyCell('td', cell, '      '));
            }
            lines.push('    </tr>');
        }
        lines.push('  </tbody>');
        lines.push('</table>');

        const newHTML = '\n' + lines.join('\n') + '\n';
        ed.value = val.substring(0, tStart) + newHTML + val.substring(tEnd);
        App.render(); US.snap();
    },

    // 언어별 주석 기호 반환  // 언어별 주석 기호 반환
    _cmt(lang) {
        const hash = ['python', 'r', 'ruby', 'bash', 'shell', 'sh', 'perl', 'yaml', 'toml', 'powershell', 'coffee'];
        const dash = ['sql', 'haskell', 'lua', 'ada'];
        const pct = ['matlab', 'latex', 'tex'];
        const semi = ['lisp', 'clojure', 'scheme'];
        const html = ['html', 'xml', 'markdown', 'md'];
        const l = lang.toLowerCase();
        if (hash.some(x => l.startsWith(x))) return '#';
        if (dash.some(x => l.startsWith(x))) return '--';
        if (pct.some(x => l.startsWith(x))) return '%';
        if (semi.some(x => l.startsWith(x))) return ';';
        if (html.some(x => l.startsWith(x))) return '<!--';
        return '//';// js, ts, java, c, cpp, go, swift, kotlin, rust, …
    },
    // Direct code block with last used language (for Alt+C hotkey)
    codeBlockDirect() {
        const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd;
        const cmt = this._cmt(lastCodeLang);
        const placeholder = cmt === '<!--' ? `<!-- 코드 입력 -->` : cmt + ' 코드 입력';
        const sel = ed.value.substring(s, e) || placeholder;
        ins(ed, s, e, `\n\`\`\`${lastCodeLang}\n${sel}\n\`\`\`\n`);
    },
    // Code block from modal (toolbar ⌨ button)
    codeBlockModal() {
        const lang = el('code-lang').value; lastCodeLang = lang || lastCodeLang;
        const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd;
        const cmt = this._cmt(lastCodeLang);
        const placeholder = cmt === '<!--' ? `<!-- 코드 입력 -->` : cmt + ' 코드 입력';
        const sel = ed.value.substring(s, e) || placeholder;
        ins(ed, s, e, `\n\`\`\`${lastCodeLang}\n${sel}\n\`\`\`\n`);
        App.hideModal('code-modal');
    },
    pageBreak() { const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, '\n\n<div class="page-break"></div>\n\n') },
    lineBreak() { const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, '<br>\n') },
    insertNbsp() { const ed = this.ed(); if (!ed) return; const s = ed.selectionStart, e = ed.selectionEnd; ins(ed, s, e, '&nbsp;'); US.snap(); },
    link() { const text = el('link-text').value || '링크'; const url = el('link-url').value || '#'; const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, `[${text}](${url})`); App.hideModal('link-modal'); el('link-text').value = ''; el('link-url').value = '' },
    image() { const alt = el('img-alt').value || '이미지'; const url = el('img-url').value || '#'; const ed = this.ed(), s = ed.selectionStart; ins(ed, s, s, `![${alt}](${url})`); if (url.startsWith('data:image') && typeof ImgStore !== 'undefined') ImgStore.save(url, alt); el('img-alt').value = ''; el('img-url').value = ''; App.hideModal('image-modal') },
    math() { const ed = this.ed(), s = ed.selectionStart, e = ed.selectionEnd, sel = ed.value.substring(s, e); ins(ed, s, e, sel ? `$$\n${sel}\n$$` : '\n$$\n\\phi = \\frac{\\lambda_2}{c^2}\n$$\n') },
    footnote() {
        const ed = this.ed();
        const pos = ed.selectionStart;
        const val = ed.value;
        const n = Math.floor((val.match(/\[\^\d+\]/g) || []).length / 2) + 1;
        const marker = `[^${n}]`;
        const defLine = `\n[^${n}]: <span style="font-size:9pt">각주 내용.</span>`;
        ed.value = val.substring(0, pos) + marker + val.substring(pos) + defLine;
        ed.setSelectionRange(pos + marker.length, pos + marker.length);
        App.render(); US.snap();
    },
    dupLine() {
        const ed = this.ed();
        const s = ed.selectionStart, e = ed.selectionEnd;
        if (s !== e) {
            // 선택 영역이 있으면 — 선택한 텍스트를 그대로 복제해서 바로 뒤에 삽입
            const sel = ed.value.substring(s, e);
            // 줄 경계에 맞게: 선택 끝 위치 뒤에 삽입
            // 선택이 줄 중간일 수도 있으므로 그냥 선택 직후에 붙임
            const insert = '\n' + sel;
            ed.value = ed.value.substring(0, e) + insert + ed.value.substring(e);
            // 복제된 부분을 선택 상태로 표시
            ed.setSelectionRange(e + 1, e + 1 + sel.length);
            ed.focus(); App.render(); US.snap();
        } else {
            // 선택 없으면 커서가 있는 줄 복제 (기존 동작)
            const { le, text } = getCL(ed);
            ins(ed, le, le, '\n' + text);
        }
    },
    // Alt+↑/↓ — 현재 줄(또는 선택 줄들)을 위/아래로 이동
    moveLine(dir) {
        const ed = this.ed();
        const val = ed.value;
        const ss = ed.selectionStart;
        const se = ed.selectionEnd;
        const lines = val.split('\n');

        // 1. 선택 범위가 포함된 시작/끝 줄 찾기 및 시작점의 절대 위치 계산
        let pos = 0;
        let startLine = -1, endLine = -1;
        let startLineAbsPos = 0;

        for (let i = 0; i < lines.length; i++) {
            const lEnd = pos + lines[i].length;
            if (startLine === -1 && ss <= lEnd) {
                startLine = i;
                startLineAbsPos = pos; // 선택된 블록이 시작되는 문자 위치 저장
            }
            if (se - (ss === se ? 0 : 1) <= lEnd) {
                endLine = i;
                break;
            }
            pos += lines[i].length + 1;
        }

        if (startLine < 0) startLine = 0;
        if (endLine < 0) endLine = startLine;

        // 경계 검사
        if (dir === -1 && startLine === 0) return;
        if (dir === 1 && endLine === lines.length - 1) return;

        // 2. 상대적 커서 오프셋 저장 (블록 시작점 기준)
        const offsetStart = ss - startLineAbsPos;
        const offsetEnd = se - startLineAbsPos;

        // 3. 줄 이동 로직
        const block = lines.splice(startLine, endLine - startLine + 1);
        const insertAt = (dir === -1) ? startLine - 1 : startLine + 1;
        lines.splice(insertAt, 0, ...block);
        ed.value = lines.join('\n');

        // 4. 이동 후의 새로운 시작 위치 계산
        let newBlockStartPos = 0;
        for (let i = 0; i < insertAt; i++) {
            newBlockStartPos += lines[i].length + 1;
        }

        // 5. 저장했던 오프셋을 적용하여 커서/선택영역 복구
        ed.setSelectionRange(newBlockStartPos + offsetStart, newBlockStartPos + offsetEnd);

        ed.focus();
        App.render();
        US.snap();
    },
    tabInTable(ed, ev) { const val = ed.value, pos = ed.selectionStart; const ls = val.lastIndexOf('\n', pos - 1) + 1, le = val.indexOf('\n', pos); const ln = val.substring(ls, le === -1 ? val.length : le); if (!ln.trim().startsWith('|')) return false; ev.preventDefault(); const pipes = []; for (let i = ls; i < (le === -1 ? val.length : le); i++)if (val[i] === '|') pipes.push(i); const nx = pipes.find(p => p > pos), nn = nx !== undefined ? pipes.find(p => p > nx) : undefined; if (nx !== undefined && nn !== undefined) ed.setSelectionRange(nx + 1, nn); return true },
    enterInTable(ed, ev) { const val = ed.value, pos = ed.selectionStart; const ls = val.lastIndexOf('\n', pos - 1) + 1, le = val.indexOf('\n', pos); const ln = val.substring(ls, le === -1 ? val.length : le); if (!ln.trim().startsWith('|') || /^\|[\s:|-]+\|$/.test(ln.trim())) return false; ev.preventDefault(); const cols = ln.split('|').filter(c => c.trim() !== '').length; ins(ed, le === -1 ? val.length : le, le === -1 ? val.length : le, '\n|' + ' 셀 |'.repeat(cols)); return true },

    /* ── 선택 텍스트 → Markdown 표 변환 (Alt+7) ────────────
       지원 구분자: 쉼표(,) / 탭(\t) / 파이프(|) / 세미콜론(;)
       첫 행 → 헤더, 두 번째 행 → 구분선, 나머지 → 데이터      */
    textToTable() {
        const ed  = el('editor');
        if (!ed) return;
        const s   = ed.selectionStart;
        const e   = ed.selectionEnd;
        const sel = ed.value.slice(s, e).trim();
        if (!sel) { App._toast('⚠ 변환할 텍스트를 먼저 선택하세요'); return; }

        const rawLines = sel.split('\n').map(l => l.trim()).filter(l => l);
        if (rawLines.length < 1) { App._toast('⚠ 선택된 텍스트가 없습니다'); return; }

        /* 구분자 자동 감지 */
        const detectSep = (line) => {
            if (line.includes('\t')) return '\t';
            if (line.includes('|'))  return '|';
            if (line.includes(';'))  return ';';
            return ',';
        };
        const sep = detectSep(rawLines[0]);

        /* 각 행을 셀 배열로 파싱 */
        const parseRow = (line) => {
            /* 파이프 구분 시 앞뒤 | 제거 */
            if (sep === '|') line = line.replace(/^\|/, '').replace(/\|$/, '');
            return line.split(sep).map(c => c.trim());
        };

        const rows = rawLines.map(parseRow);
        const colCount = Math.max(...rows.map(r => r.length));

        /* 열 수 맞추기 */
        rows.forEach(r => { while (r.length < colCount) r.push(''); });

        /* Markdown 표 생성 */
        const mkRow = cells => '| ' + cells.join(' | ') + ' |';
        const header = mkRow(rows[0]);
        const divider = '| ' + Array(colCount).fill('---').join(' | ') + ' |';
        const body = rows.slice(1).map(mkRow).join('\n');
        const table = header + '\n' + divider + (body ? '\n' + body : '');

        ed.setRangeText(table, s, e, 'end');
        US.snap(); TM.markDirty(); App.render();
        App._toast('✓ 표 변환 완료 (' + colCount + '열 × ' + rows.length + '행)');
    },

    /* ── 마크다운 표 → HTML 표 변환 ─────────────────────
       커서가 표 안에 있거나, 표 영역을 선택한 상태에서 실행    */
    mdTableToHtml() {
        const ed = el('editor');
        if (!ed) return;
        const val = ed.value;
        const pos = ed.selectionStart;
        const selEnd = ed.selectionEnd;

        /* 선택 영역이 있으면 그 범위에서 표 찾기, 없으면 커서 위치 기준 */
        let tableStart = -1, tableEnd = -1;

        const lines = val.split('\n');
        let charPos = 0;
        const lineStarts = lines.map(l => { const s = charPos; charPos += l.length + 1; return s; });

        /* 커서/선택 위치의 라인 찾기 */
        let cursorLine = 0;
        for (let i = 0; i < lineStarts.length; i++) {
            if (lineStarts[i] <= pos) cursorLine = i;
        }

        /* 커서 라인이 표인지 확인 */
        const isTableLine = (line) => line.trim().startsWith('|');

        /* 표 블록 범위 찾기 */
        let tStart = cursorLine, tEnd = cursorLine;
        while (tStart > 0 && isTableLine(lines[tStart - 1])) tStart--;
        while (tEnd < lines.length - 1 && isTableLine(lines[tEnd + 1])) tEnd++;

        if (!isTableLine(lines[cursorLine])) {
            App._toast('⚠ 커서를 표 안에 위치시키거나 표를 선택하세요');
            return;
        }

        tableStart = lineStarts[tStart];
        tableEnd = (tEnd < lines.length - 1) ? lineStarts[tEnd + 1] - 1 : val.length;

        const tableLines = lines.slice(tStart, tEnd + 1);

        /* 파싱 */
        const parseRow = (line) => {
            return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
        };

        const dataLines = tableLines.filter(l => !/^\|[\s:|-]+\|/.test(l.trim()));
        if (dataLines.length < 1) { App._toast('⚠ 표 데이터를 찾을 수 없습니다'); return; }

        const headerRow = parseRow(dataLines[0]);
        const bodyRows  = dataLines.slice(1).map(parseRow);

        /* HTML 생성 */
        const indent = '  ';
        let html = '<table>\n';
        html += indent + '<thead>\n';
        html += indent + indent + '<tr>\n';
        headerRow.forEach(cell => { html += indent + indent + indent + `<th>${cell}</th>\n`; });
        html += indent + indent + '</tr>\n';
        html += indent + '</thead>\n';
        if (bodyRows.length) {
            html += indent + '<tbody>\n';
            bodyRows.forEach(row => {
                html += indent + indent + '<tr>\n';
                row.forEach(cell => { html += indent + indent + indent + `<td>${cell}</td>\n`; });
                html += indent + indent + '</tr>\n';
            });
            html += indent + '</tbody>\n';
        }
        html += '</table>';

        ed.setRangeText(html, tableStart, tableEnd, 'end');
        US.snap(); TM.markDirty(); App.render();
        App._toast(`✓ HTML 표 변환 완료 (${headerRow.length}열 × ${dataLines.length}행)`);
    },
};

/* DelConfirm → js/ui/del-confirm.js */

/* EZ → js/ui/ez.js */

/* EditorLineHighlight → js/editor/line-highlight.js */

/* EditorAutoPair → js/editor/auto-pair.js */

/* AuthorInfo → js/ui/author-info.js */

/* FS (Font Size Manager) → js/editor/font-size.js */

/* FP → js/ui/fp.js */

/* STATS → js/ui/stats.js */

/* HK, hkKey -> js/core/hotkey.js */

function handleKey(e) {
    const edi = el('editor');
    const inEd = document.activeElement === edi;
    const k = hkKey(e);

    /* ── 괄호·따옴표 자동쌍 & 선택 감싸기: ( [ " ' (설정 ON일 때만) ── */
    if (inEd && typeof EditorAutoPair !== 'undefined' && EditorAutoPair.handleKey(e)) return;

    /* ── Ctrl+H: 찾기/바꾸기 (브라우저 히스토리 등에 빼앗기지 않도록 우선 처리) ── */
    if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        e.stopPropagation();
        if (typeof App !== 'undefined' && App.toggleFind) App.toggleFind();
        return;
    }

    /* ── Alt+4: 전체 다크/라이트 토글 (항상 동작) ── */
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.code === 'Digit4' || e.key === '4')) {
        e.preventDefault();
        if (typeof App !== 'undefined' && App.toggleTheme) App.toggleTheme();
        return;
    }

    /* ── Ctrl+9: 에디터 축소, Ctrl+0: 에디터 확대 ── */
    if ((e.ctrlKey || e.metaKey) && e.key === '9') { e.preventDefault(); EZ.dec(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key === '0') { e.preventDefault(); EZ.inc(); return; }

    /* ── Tab / Shift+Tab: 에디터 들여쓰기 (표 안이면 셀 이동 우선) ──────
       표 안 → tabInTable()이 처리 (셀 이동)
       표 밖 + 선택 없음:
           Tab        → 커서 위치에 공백 2칸 삽입
           Shift+Tab  → 줄 앞 공백 2칸 제거
       표 밖 + 다중 줄 선택:
           Tab        → 선택된 각 줄 앞에 공백 2칸 추가
           Shift+Tab  → 선택된 각 줄 앞 공백 2칸 제거
    ─────────────────────────────────────────────────────────────── */
    if (e.key === 'Tab' && inEd) {
        if (ED.tabInTable(edi, e)) return;   // 표 안: 셀 이동
        e.preventDefault();
        const val = edi.value;
        const ss = edi.selectionStart;
        const se = edi.selectionEnd;
        const INDENT = '  ';                  // 공백 2칸

        if (ss === se) {
            /* 선택 없음: 커서 위치에 공백 삽입 or 줄 앞 제거 */
            if (e.shiftKey) {
                const ls = val.lastIndexOf('\n', ss - 1) + 1;
                if (val.slice(ls, ls + INDENT.length) === INDENT) {
                    edi.value = val.slice(0, ls) + val.slice(ls + INDENT.length);
                    edi.setSelectionRange(Math.max(ls, ss - INDENT.length), Math.max(ls, ss - INDENT.length));
                }
            } else {
                edi.value = val.slice(0, ss) + INDENT + val.slice(se);
                edi.setSelectionRange(ss + INDENT.length, ss + INDENT.length);
            }
        } else {
            /* 다중 줄 선택: 각 줄 일괄 indent / dedent */
            const ls = val.lastIndexOf('\n', ss - 1) + 1;   // 선택 첫 줄 시작
            const block = val.slice(ls, se);
            let newBlock;
            if (e.shiftKey) {
                newBlock = block.replace(/^  /gm, '');
            } else {
                newBlock = block.replace(/^/gm, INDENT);
            }
            const delta = newBlock.length - block.length;
            edi.value = val.slice(0, ls) + newBlock + val.slice(se);
            edi.setSelectionRange(ls, se + delta);
        }
        US.snap(); TM.markDirty(); App.render();
        return;
    }

    /* ── Enter: 표 행 자동 추가 비활성화 (행 추가는 툴바 +행 버튼 사용) ── */
    // if (e.key === 'Enter' && inEd) { if (ED.enterInTable(edi, e)) return; }

    /* ── Alt+Enter: 현재 줄 목록 수준 유지하며 줄바꿈 ──────────────────────
       - "  - 내용"   → "\n  - "  (같은 indent + bullet)
       - "  1. 내용"  → "\n  2. " (같은 indent + 다음 번호)
       - "  - [ ] "   → "\n  - [ ] " (체크박스)
       - prefix 없음  → "\n" 일반 줄바꿈
    ─────────────────────────────────────────────────────────────────────── */
    if (e.altKey && e.key === 'Enter' && inEd) {
        e.preventDefault();
        const { text } = getCL(edi);
        const pos = edi.selectionStart;
        const m = text.match(/^(\s*)([-*+]\s+(?:\[[ xX]\]\s+)?|(\d+)\.\s+)/);
        let insertion;
        if (m) {
            const indent = m[1];
            const num    = m[3];
            if (num !== undefined) {
                insertion = '\n' + indent + (parseInt(num, 10) + 1) + '. ';
            } else if (/\[[ xX]\]/.test(m[2])) {
                insertion = '\n' + indent + '- [ ] ';
            } else {
                insertion = '\n' + indent + m[2];
            }
        } else {
            insertion = '\n';
        }
        ins(edi, pos, edi.selectionEnd, insertion);
        return;
    }

    /* ── Alt+5 / Alt+6: 목록 변환 (Windows 등에서 e.key가 %^ 로 오므로 e.code로만 판별) ── */
    if (inEd && e.altKey && !e.ctrlKey && !e.metaKey &&
        (e.code === 'Digit5' || e.code === 'Digit6')) {
        e.preventDefault();
        e.stopPropagation();
        if (e.code === 'Digit5') ED.textToList();
        else ED.textToNumberedList();
        return;
    }

    /* ── Alt+I: 이미지 링크 만들기 (선택 URL → HTML img) ── */
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
        if (typeof App !== 'undefined' && App.makeImageLink) App.makeImageLink();
        return;
    }

    const dispatch = HK.getDispatch();
    const fn = dispatch[k];
    if (!fn) return;

    /* ── action prefix로 전역/에디터 전용 분기 ─────────────────
       view.* / app.* / fs.*  → 전역: 에디터 포커스와 무관하게 실행
       ed.*                   → 에디터 전용: 에디터에 포커스가 있을 때만 실행
       이 구분 덕분에 Alt+3으로 preview 전환 후에도 Alt+1,2가 정상 동작함 */
    const actionId = HK.getActionId(fn);
    const isGlobal = actionId && !actionId.startsWith('ed.');

    if (isGlobal) {
        e.preventDefault();
        fn();
    } else if (inEd) {
        e.preventDefault();
        fn();
    }
    /* ed.* 이고 에디터 포커스가 없으면: preventDefault 없이 return → 브라우저 기본 동작 유지 */
}


/* ═══════════════════════════════════════════════════════════
   TOOLTIP
═══════════════════════════════════════════════════════════ */
function initTooltip() {
    const tip = el('tooltip'); let t;
    document.addEventListener('mouseover', e => { const target = e.target.closest('[data-tooltip]'); if (!target) return; clearTimeout(t); t = setTimeout(() => { const key = target.dataset.key; tip.innerHTML = target.dataset.tooltip + (key ? ` <span class="tt-key">${key}</span>` : ''); tip.classList.add('vis'); let x = e.clientX + 12, y = e.clientY + 16; if (x + 260 > window.innerWidth) x = e.clientX - 260; if (y + 40 > window.innerHeight) y = e.clientY - 40; tip.style.left = x + 'px'; tip.style.top = y + 'px' }, 300) });
    document.addEventListener('mouseout', () => { clearTimeout(t); tip.classList.remove('vis') });
}

/* ═══════════════════════════════════════════════════════════
   MAIN APP
═══════════════════════════════════════════════════════════ */
const App = {
    rm: false, rt: null, colorMode: 'text', capType: 'table',

    init() {
        TM.init(); CM.load(); initTooltip(); SS.init(); FS.update(); LN.init(); EZ.init();
        if (typeof EditorLineHighlight !== 'undefined') EditorLineHighlight.init();
        if (typeof EditorAutoPair !== 'undefined') EditorAutoPair.init();
        SB.init();  /* 저장된 소스 탭(로컬/GitHub) 복원 */
        /* 테마 복원: 전체 / 에디터 / PV 각각 */
        try {
            const globalTheme = localStorage.getItem('mdpro_theme');
            if (globalTheme === 'light') document.documentElement.dataset.theme = 'light';
            const edTheme = localStorage.getItem('mdpro_editor_theme');
            const ep = document.getElementById('editor-pane');
            if (ep && edTheme) ep.dataset.editorTheme = edTheme;
            if (typeof PV !== 'undefined' && PV.initTheme) PV.initTheme();
        } catch (e) {}
        App._updateEditorThemeBtn();
        /* FM.restore는 DOMContentLoaded에서 별도 호출 */
        /* HK 초기화: 앱 시작 시 load + rebuild 해야 핫키가 작동함 */
        try { HK._initDispatch(); } catch(e) {}
        /* Word Wrap 복원: 저장값이 '0'이면 OFF, 그 외에는 ON(기본) */
        try {
            const wrap = document.getElementById('editor-wrap');
            if (wrap) {
                if (localStorage.getItem('mdpro_editor_wordwrap') !== '0') wrap.classList.add('editor-word-wrap');
                else wrap.classList.remove('editor-word-wrap');
            }
        } catch (e) {}
        /* Ctrl+H: 찾기/바꾸기 — 캡처 단계에서 선점해 브라우저(히스토리 등)에 빼앗기지 않도록 */
        CoreEvents.init();
        // Set default view button state
        const splitBtn = el('vm-split'); if (splitBtn) splitBtn.classList.add('active');
        const edi = el('editor');
        el('tmpl-grid').innerHTML = TMPLS.map((t, i) => `<div class="tmpl-card" onclick="App.insertTmpl(${i})"><h4>${t.icon} ${t.name}</h4><p>${t.desc}</p></div>`).join('');

        if (!edi.value) edi.value = this.sample();
        this.render(); US.snap();

/* ── Split Resizer 초기화 ──────────────────────────────── */
(function initSplitResizer() {
    const resizer    = document.getElementById('split-resizer');
    const edPane     = document.getElementById('editor-pane');
    const pvPane     = document.getElementById('preview-pane');
    const wrap       = document.getElementById('editor-wrap');
    if (!resizer || !edPane || !pvPane || !wrap) return;

    /* 저장된 비율 복원 */
    const saved = parseFloat(localStorage.getItem('mdpro_split_ratio') || '0.5');
    function applyRatio(r) {
        r = Math.max(0.15, Math.min(0.85, r));
        edPane.style.flex  = 'none';
        pvPane.style.flex  = 'none';
        edPane.style.width = (r * 100).toFixed(2) + '%';
        pvPane.style.width = ((1 - r) * 100).toFixed(2) + '%';
    }
    applyRatio(saved);

    /* 숨김 패널일 때는 flex 리셋 */
    const resetFlex = () => {
        if (edPane.classList.contains('hidden')) { pvPane.style.flex = '1'; pvPane.style.width = ''; }
        else if (pvPane.classList.contains('hidden')) { edPane.style.flex = '1'; edPane.style.width = ''; }
    };

    let startX = 0, startEdW = 0, totalW = 0, dragging = false;

    function startDrag(clientX) {
        if (edPane.classList.contains('hidden') || pvPane.classList.contains('hidden')) return;
        dragging  = true;
        startX    = clientX;
        startEdW  = edPane.getBoundingClientRect().width;
        totalW    = wrap.getBoundingClientRect().width - resizer.offsetWidth;
        document.body.classList.add('resizing');
        resizer.classList.add('dragging');
    }
    function moveDrag(clientX) {
        if (!dragging) return;
        const dx    = clientX - startX;
        const newW  = Math.max(120, Math.min(totalW - 120, startEdW + dx));
        const ratio = newW / totalW;
        applyRatio(ratio);
    }
    function endDrag() {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove('resizing');
        resizer.classList.remove('dragging');
        const r = edPane.getBoundingClientRect().width / (wrap.getBoundingClientRect().width - resizer.offsetWidth);
        localStorage.setItem('mdpro_split_ratio', r.toFixed(4));
    }

    resizer.addEventListener('mousedown', e => {
        if (e.button !== 0) return;
        e.preventDefault();
        startDrag(e.clientX);
    });

    document.addEventListener('mousemove', e => {
        if (!dragging) return;
        moveDrag(e.clientX);
    });

    document.addEventListener('mouseup', e => {
        endDrag();
    });

    /* 터치: 모바일에서 에디터·미리보기 구분선 조절 (리사이저에서만 시작, UI 내에서만 동작) */
    resizer.addEventListener('touchstart', e => {
        if (e.touches.length !== 1) return;
        e.preventDefault();
        startDrag(e.touches[0].clientX);
    }, { passive: false });

    document.addEventListener('touchmove', e => {
        if (!dragging) return;
        if (e.touches.length !== 1) return;
        e.preventDefault();
        moveDrag(e.touches[0].clientX);
    }, { passive: false });

    document.addEventListener('touchend', endDrag);
    document.addEventListener('touchcancel', endDrag);

    /* 더블클릭: 50:50 리셋 */
    resizer.addEventListener('dblclick', () => {
        applyRatio(0.5);
        localStorage.setItem('mdpro_split_ratio', '0.5');
    });

    /* setView 호출 시 flex 리셋 필요 */
    const origSetView = App.setView.bind(App);
    App.setView = function(m) {
        origSetView(m);
        edPane.style.flex = ''; edPane.style.width = '';
        pvPane.style.flex = ''; pvPane.style.width = '';
        if (m === 'split') {
            const r = parseFloat(localStorage.getItem('mdpro_split_ratio') || '0.5');
            applyRatio(r);
        }
        resetFlex();
    };
})();
    },

    render() {
        const edi = el('editor'); const md = edi.value, title = el('doc-title').value;
        clearTimeout(this.rt);
        this.rt = setTimeout(() => { Render.run(md, title); }, 120);
        this.updCursor();
    },

    updCursor() { CursorUI.updCursor(); },
    updFmtBtns() { CursorUI.updFmtBtns(); },
    showErrs(errs) { const ec = el('error-count'), sep = el('ec-sep'), list = el('ep-list'), panel = el('error-panel'); if (!errs.length) { ec.textContent = ''; sep.style.display = 'none'; panel.classList.remove('vis'); return } ec.textContent = `⚠ ${errs.length}개 오류`; sep.style.display = 'block'; list.innerHTML = errs.map(e => `<div class="error-item">${e}</div>`).join('') },
    toggleErr() { el('error-panel').classList.toggle('vis') }, closeErr() { el('error-panel').classList.remove('vis') },
    toggleSidebar() { el('app').classList.toggle('ns') },
    setView(m) { el('editor-pane').classList.toggle('hidden', m === 'preview'); el('preview-pane').classList.toggle('hidden', m === 'editor') },
    setViewCycle(m) {
        this.setView(m);
        ['split', 'editor', 'preview'].forEach(v => { const b = el('vm-' + v); if (b) b.classList.toggle('active', v === m) });
    },
    toggleTheme() {
        const isLight = document.documentElement.dataset.theme === 'light';
        const nextLight = !isLight;
        document.documentElement.dataset.theme = nextLight ? 'light' : '';
        const ep = document.getElementById('editor-pane');
        if (ep) ep.dataset.editorTheme = nextLight ? 'light' : 'dark';
        if (typeof PV !== 'undefined' && PV.setDark) PV.setDark(!nextLight);
        try {
            localStorage.setItem('mdpro_theme', nextLight ? 'light' : 'dark');
            localStorage.setItem('mdpro_editor_theme', nextLight ? 'light' : 'dark');
        } catch (e) {}
        App._updateEditorThemeBtn();
    },
    toggleWordWrap() {
        const wrap = document.getElementById('editor-wrap');
        if (!wrap) return;
        const on = wrap.classList.toggle('editor-word-wrap');
        try { localStorage.setItem('mdpro_editor_wordwrap', on ? '1' : '0'); } catch (e) {}
    },
    setTheme(theme) {
        const isLight = theme === 'light';
        document.documentElement.dataset.theme = isLight ? 'light' : '';
        const ep = document.getElementById('editor-pane');
        if (ep) ep.dataset.editorTheme = isLight ? 'light' : 'dark';
        if (typeof PV !== 'undefined' && PV.setDark) PV.setDark(!isLight);
        try {
            localStorage.setItem('mdpro_theme', isLight ? 'light' : 'dark');
            localStorage.setItem('mdpro_editor_theme', isLight ? 'light' : 'dark');
        } catch (e) {}
        App._updateEditorThemeBtn();
    },
    toggleEditorTheme() {
        const ep = document.getElementById('editor-pane');
        if (!ep) return;
        const cur = ep.dataset.editorTheme || (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
        const next = cur === 'light' ? 'dark' : 'light';
        ep.dataset.editorTheme = next;
        try { localStorage.setItem('mdpro_editor_theme', next); } catch (e) {}
        App._updateEditorThemeBtn();
    },
    _updateEditorThemeBtn() {
        const ep = document.getElementById('editor-pane');
        const btn = document.getElementById('ed-theme-btn');
        if (!btn) return;
        const isLight = ep ? (ep.dataset.editorTheme === 'light') : (document.documentElement.dataset.theme === 'light');
        btn.textContent = isLight ? '◐' : '◑';
        btn.title = isLight ? '에디터 라이트 (클릭 시 다크)' : '에디터 다크 (클릭 시 라이트)';
    },
    toggleRM() { this.rm = !this.rm; el('rm-badge').classList.toggle('vis', this.rm); el('mode-ind').textContent = this.rm ? 'RESEARCH' : 'NORMAL'; PR.rm = this.rm; PW.setRM(this.rm); this.render() },
    showHK() { HK.open() }, hideHK() { HK.close() },
    showCode() { el('code-modal').classList.add('vis') },
    showLink() { el('link-modal').classList.add('vis'); setTimeout(() => el('link-text').focus(), 50) },
    showImg() {
        // reset drop zone
        el('img-drop-text').textContent = '🖼 클릭 또는 드래그';
        el('img-drop-text').style.color = '';
        el('img-dropzone').style.borderColor = ''; el('img-dropzone').style.background = '';
        if (typeof AiImage !== 'undefined') AiImage.switchTab('insert');
        _showImgpv(el('img-url') ? el('img-url').value.trim() : '');
        _bindImgUrlToImgpv();
        _bindImgCodeToPreview();
        el('image-modal').classList.add('vis'); setTimeout(() => el('img-alt').focus(), 50);
    },
    makeImageLink() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        let url = (ed.value.slice(s, e) || '').trim();
        if (!url) {
            alert('URL을 선택한 뒤 Alt+I를 누르거나 🖼 링크 버튼을 누르세요.');
            return;
        }
        if (!/^https?:\/\//i.test(url) && !/^data:image\//i.test(url)) {
            alert('선택한 내용이 URL이 아닙니다.\nhttps://... 또는 data:image/... 형식을 선택해 주세요.');
            return;
        }
        const isImageUrl = /^data:image\//i.test(url) || /\.(jpe?g|png|gif|webp|svg|bmp|ico)(\?.*)?$/i.test(url);
        let tag;
        if (isImageUrl) {
            const width = '500';
            const esc = url.replace(/"/g, '&quot;');
            tag = '<img src="' + esc + '" border="0" width="' + width + '">';
        } else {
            const label = prompt('링크 표시 텍스트 (비우면 URL 그대로 표시):', '');
            if (label === null) return;
            const text = label.trim() !== '' ? label.trim() : url;
            const escHref = url.replace(/"/g, '&quot;').replace(/&/g, '&amp;');
            const escText = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            tag = '<a href="' + escHref + '">' + escText + '</a>';
        }
        if (typeof ED !== 'undefined' && typeof ED.ins === 'function') {
            ED.ins(ed, s, e, tag);
        } else {
            ed.setRangeText(tag, s, e, 'end');
        }
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    openSelectionAsLink() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const text = (ed.value.slice(s, e) || '').trim();
        if (!text) {
            alert('링크로 넣을 URL 또는 텍스트를 선택한 뒤 Shift+Alt+I를 누르거나 🔗 새창 버튼을 누르세요.');
            return;
        }
        let href, label;
        if (/^https?:\/\//i.test(text)) {
            href = text;
            const input = prompt('링크 표시 텍스트 (비우면 URL 그대로 표시):', '');
            if (input === null) return;
            label = input.trim() !== '' ? input.trim() : text;
        } else {
            const urlInput = prompt('링크 URL:', text);
            if (urlInput === null) return;
            href = (urlInput || '').trim() || text;
            const textInput = prompt('링크 표시 텍스트 (비우면 URL 표시):', text);
            if (textInput === null) return;
            label = (textInput || '').trim() !== '' ? textInput.trim() : href;
        }
        const escHref = href.replace(/"/g, '&quot;').replace(/&/g, '&amp;');
        const escLabel = label.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const tag = '<a href="' + escHref + '" target="_blank" rel="noopener">' + escLabel + '</a>';
        if (typeof ED !== 'undefined' && typeof ED.ins === 'function') {
            ED.ins(ed, s, e, tag);
        } else {
            ed.setRangeText(tag, s, e, 'end');
        }
        ed.focus();
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    showCite() { CM.open(); el('cite-modal').classList.add('vis') },
    showStats() { STATS.show() },
    /* ── 스마트 저장 (Ctrl+S) ──────────────────────────── */
    async smartSave() {
        const tab = TM.getActive();
        if (!tab) return;
        if (tab.ghPath) { App._openGHSaveModal(tab); return; }
        /* 파일핸들 있으면 바로 덮어쓰기 */
        if (tab._fileHandle) {
            try {
                const perm = await tab._fileHandle.queryPermission({ mode: 'readwrite' });
                if (perm === 'granted') {
                    await LocalFS.writeToHandle(tab._fileHandle, el('editor').value);
                    TM.markClean(tab.id); TM.renderTabs();
                    App._toast('\u{1F4BE} \uC800\uC7A5\uB428 \u2014 ' + tab.title);
                    return;
                }
            } catch(e) { /* 권한 없으면 폴백 */ }
        }
        App.showSaveDlg();
    },
    showSaveDlg() {
        const tab = TM.getActive();
        if (tab && tab.ghPath) { App._openGHSaveModal(tab); return; }
        const infoEl = el('save-current-info');
        const pathEl = el('save-current-path');
        if (infoEl && pathEl) {
            if (tab && (tab.filePath || tab._fileHandle)) {
                pathEl.textContent = tab.filePath || tab.title;
                infoEl.style.display = '';
            } else { infoEl.style.display = 'none'; }
        }
        el('save-modal').classList.add('vis');
    },
    /* ── GitHub 커밋 (저장 모달 → Git 버튼) ─────────── */
    async saveAndGitCommit() {
        App.hideModal('save-modal');
        const tab = TM.getActive();
        if (!tab) return;
        if (!GH.isConnected()) {
            alert('GitHub\uC774 \uC5F0\uACB0\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.\n\uD83D\uDC19 GitHub \uD0ED \u2192 \uC124\uC815\uC5D0\uC11C \uBA3C\uC800 \uC5F0\uACB0\uD558\uC138\uC694.');
            return;
        }
        if (!tab.ghPath) {
            const ghCfg = GH.cfg;
            const titleHasExt = /\.[a-zA-Z0-9]+$/.test(tab.title || '');
            const fname = (tab.title || 'untitled') + (titleHasExt ? '' : '.md');
            const basePart = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const ghPath = basePart + fname;
            const ok = confirm(`GitHub에 새 파일로 커밋합니다.\n\n경로: ${ghPath}\n\n계속하시겠습니까?`);
            if (!ok) return;
            tab.ghPath   = ghPath;
            tab.ghBranch = ghCfg.branch;
        }
        App._openGHSaveModal(tab);
    },
    showModal(id)  { el(id).classList.add('vis'); },

    /* ── 경로/커밋메시지 자동 갱신 (위치·파일명 변경 시) ─── */
    _ghSaveUpdatePath() {
        const folderEl = el('gh-save-folder');
        const fnameEl  = el('gh-save-filename');
        const pathEl   = el('gh-save-file-path');
        const msgEl    = el('gh-save-commit-msg');
        if (!folderEl || !fnameEl || !pathEl) return;
        const folder = (folderEl.value || '/').trim();
        const fname  = (fnameEl.value || '').trim();
        const fullPath = folder === '/' ? fname : (folder + '/' + fname);
        if (pathEl) pathEl.value = fullPath;
        /* 커밋 메시지 = 날짜시간 + 폴더/파일명 */
        App._ghSaveUpdateCommitMsg(fullPath || '');
    },
    /* ── 경로 입력란에서 폴더/파일명 파싱 (직접 수정 시) ─── */
    _ghSaveUpdateFromPath() {
        const pathEl   = el('gh-save-file-path');
        const folderEl = el('gh-save-folder');
        const fnameEl  = el('gh-save-filename');
        if (!pathEl) return;
        const p = (pathEl.value || '').trim().replace(/^\/+/, '');
        const lastSlash = p.lastIndexOf('/');
        const folder = lastSlash >= 0 ? p.slice(0, lastSlash) : '/';
        const fname = lastSlash >= 0 ? p.slice(lastSlash + 1) : p;
        if (folderEl) folderEl.value = folder;
        if (fnameEl) fnameEl.value = fname;
        App._ghSaveUpdateCommitMsg(p || '');
    },
    /* ── 커밋 메시지: 오늘날짜 시간 + 폴더/파일명 ─── */
    _ghSaveUpdateCommitMsg(pathPart) {
        const msgEl = el('gh-save-commit-msg');
        if (!msgEl) return;
        const now = new Date();
        const y = now.getFullYear(), m = String(now.getMonth() + 1).padStart(2, '0'), d = String(now.getDate()).padStart(2, '0');
        const h = String(now.getHours()).padStart(2, '0'), min = String(now.getMinutes()).padStart(2, '0'), s = String(now.getSeconds()).padStart(2, '0');
        const dateStr = `${y}-${m}-${d}`;
        const timeStr = `${h}:${min}:${s}`;
        msgEl.value = pathPart ? `${dateStr} ${timeStr} ${pathPart}` : '';
    },

    /* ── GitHub 저장 모달 열기 ──────────────────────────── */
    _openGHSaveModal(tab) {
        if (!tab) return;

        const ghCfg    = GH.cfg || {};
        const basePart = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';

        let fullPath;
        if (tab.ghPath) {
            fullPath = tab.ghPath;
        } else {
            const titleHasExt = /\.[a-zA-Z0-9]+$/.test(tab.title || '');
            const fname = (tab.title || 'untitled') + (titleHasExt ? '' : '.md');
            fullPath = basePart + fname;
        }

        /* basePath 제거 후 폴더 + 파일명 분리 (모달 UI는 basePath 제외) */
        const relFullPath = basePart && fullPath.startsWith(basePart)
            ? fullPath.slice(basePart.length) : fullPath;
        const lastSlash = relFullPath.lastIndexOf('/');
        const folder = lastSlash >= 0 ? relFullPath.slice(0, lastSlash) : '/';
        const fname = lastSlash >= 0 ? relFullPath.slice(lastSlash + 1) : relFullPath;

        /* 폴더 드롭다운 옵션 채우기 */
        const folderSelect = el('gh-save-folder');
        if (folderSelect && typeof GH.getFolderOptionsForSave === 'function') {
            folderSelect.innerHTML = GH.getFolderOptionsForSave(folder === '' ? '/' : folder);
            folderSelect.value = folder === '' ? '/' : folder;
        }

        /* 파일명 입력란 */
        const fnameInput = el('gh-save-filename');
        if (fnameInput) fnameInput.value = fname;

        /* 경로·커밋메시지 갱신 */
        App._ghSaveUpdatePath();

        /* 파일명 변경 감지 (기존 경로 대비) */
        const origPath  = tab.ghPath;
        const origName  = origPath ? origPath.split('/').pop().replace(/\.[^.]+$/, '') : null;
        const curName   = fname ? fname.replace(/\.[^.]+$/, '') : '';
        const nameChanged = origName && origName !== curName;

        const notice = el('gh-rename-notice');
        const detail = el('gh-rename-detail');
        if (notice && detail) {
            if (nameChanged) {
                const origExt  = origPath ? '.' + origPath.split('.').pop() : '.md';
                const newFolder = folder === '/' ? '' : folder + '/';
                const newPath  = newFolder + curName + origExt;
                detail.textContent = `${origPath} → ${newPath}`;
                notice.style.display = '';
                notice.dataset.oldPath = origPath;
                notice.dataset.newPath = newPath;
            } else {
                notice.style.display = 'none';
            }
        }

        const commitBtn = el('gh-save-commit-btn');
        if (commitBtn) commitBtn.textContent = nameChanged ? '🐙 커밋 (파일명 변경)' : '🐙 GitHub 커밋';

        const msgInput = el('gh-save-commit-msg');
        const device = localStorage.getItem('mdpro_device_name');
        if (device && msgInput && !msgInput.value.includes('[device:')) {
            msgInput.value += ` [device:${device}]`;
        }

        el('gh-save-modal').classList.add('vis');
    },

    /* ── GitHub 커밋 실행 ───────────────────────────────── */
    async ghSaveCommit() {
        const tab = TM.getActive();
        if (!tab) return;
        const msg      = el('gh-save-commit-msg').value.trim();
        const notice   = el('gh-rename-notice');

        /* 경로: path 입력란 우선 (직접 수정 가능) */
        const pathInput = el('gh-save-file-path');
        const ghCfg     = GH.cfg || {};
        const basePart  = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
        let relPath     = (pathInput && pathInput.value || '').trim().replace(/^\/+/, '');
        if (!relPath) {
            const folderEl = el('gh-save-folder');
            const fnameEl  = el('gh-save-filename');
            const folder   = (folderEl && folderEl.value || '/').trim();
            const fname    = (fnameEl && fnameEl.value || '').trim();
            relPath = folder === '/' ? fname : (folder + '/' + fname);
        }
        const inputPath = basePart + relPath;
        const origPath  = tab.ghPath;
        const pathChanged = inputPath && inputPath !== origPath;

        /* 경로가 변경된 경우 rename 처리, 아니면 nameChanged 기존 로직 유지 */
        const nameChanged = (!pathChanged) && notice && notice.style.display !== 'none';

        App.hideModal('gh-save-modal');

        if (pathChanged && origPath) {
            /* 경로(파일명/폴더) 변경 커밋 */
            const content = el('editor').value;
            try {
                const result = await GH.renameAndCommit(origPath, inputPath, content, msg || `Rename ${origPath} → ${inputPath}`);
                tab.ghPath  = inputPath;
                tab.ghSha   = null;
                TM.markClean(tab.id);
                TM.renderTabs();
                App._toast(`✓ 경로 변경 커밋 완료 #${result.commitSha}`);
            } catch(e) {
                alert(`커밋 실패: ${e.message}`);
            }
        } else if (pathChanged && !origPath) {
            /* 새 파일, 경로 직접 지정 */
            tab.ghPath = inputPath;
            const ghCfg = GH.cfg;
            tab.ghBranch = tab.ghBranch || ghCfg.branch;
            const ok = await GH.saveFile(tab.id, msg || `Add ${inputPath}`);
            if (ok) App._toast('✓ GitHub에 저장됨');
        } else if (nameChanged) {
            /* 파일명 변경 커밋 */
            const oldPath = notice.dataset.oldPath;
            const newPath = inputPath; /* 폴더+파일명에서 계산된 경로 사용 */
            const content = el('editor').value;
            try {
                const result = await GH.renameAndCommit(oldPath, newPath, content, msg);
                tab.ghPath  = newPath;
                tab.ghSha   = null;
                TM.markClean(tab.id);
                TM.renderTabs();
                App._toast(`✓ 파일명 변경 커밋 완료 #${result.commitSha}`);
            } catch(e) {
                alert(`커밋 실패: ${e.message}`);
            }
        } else {
            /* 일반 커밋 — 경로도 그대로 */
            if (inputPath && !origPath) tab.ghPath = inputPath;
            const ok = await GH.saveFile(tab.id, msg || `Update ${relPath || tab.title}`);
            if (ok) App._toast('✓ GitHub에 저장됨');
        }
    },

    /* ── 로컬 저장 (.md 다운로드) ───────────────────────── */
    ghSaveLocal() {
        const tab  = TM.getActive();
        const name = tab ? tab.title : 'document';
        const c    = el('editor').value;
        dlBlob(c, name.replace(/[^a-z0-9가-힣\-_. ]/gi, '_') + '.md', 'text/markdown;charset=utf-8');
        App.hideModal('gh-save-modal');
        App._toast('💾 로컬에 저장됨');
    },

    /* ── GitHub 커밋 + md-viewer Push 동시 실행 ── */
    async ghSaveAndPushViewer() {
        /* 1) 먼저 GitHub 커밋 */
        await App.ghSaveCommit();
        /* 2) 이어서 md-viewer push */
        const tab = TM.getActive();
        if (!tab) return;
        const content = el('editor').value;
        await PVShare.quickPush({ name: tab.title || 'document', content });
    },
    deleteLine() {
        const ed = el('editor');
        if (!ed) return;
        const val = ed.value, pos = ed.selectionStart;
        const s = val.lastIndexOf('\n', pos - 1) + 1;
        let e2 = val.indexOf('\n', pos);
        e2 = (e2 === -1) ? val.length : e2 + 1;
        ed.value = val.slice(0, s) + val.slice(e2);
        ed.selectionStart = ed.selectionEnd = Math.min(s, ed.value.length);
        US.snap(); TM.markDirty(); App.render();
    },
    showCommitHistory() {
        App.showModal('gh-history-modal');
        GH.loadHistory(false);
    },
    /* ── 오늘 날짜 삽입 (Shift+Alt+D): 핫키는 오늘 날짜 직접 삽입 ── */
    insertDate() {
        const ed  = el('editor');
        if (!ed) return;
        const dateStr = formatDateTime(new Date());
        const pos = ed.selectionStart;
        const end = ed.selectionEnd;
        ed.setRangeText(dateStr, pos, end, 'end');
        US.snap(); TM.markDirty(); App.render();
    },
    /* ── 날짜 삽입 모달 (버튼 클릭 시): 달력에서 선택 후 삽입 ── */
    _dateInsertCurrent: null,
    _dateInsertShowTime: false,
    openDatePickerModal() {
        this._dateInsertCurrent = new Date();
        this._dateInsertShowTime = false;
        const chk = document.getElementById('date-insert-show-time');
        if (chk) chk.checked = false;
        this._dateInsertRefresh();
        App.showModal('date-insert-modal');
    },
    toggleDateInsertShowTime() {
        const chk = document.getElementById('date-insert-show-time');
        this._dateInsertShowTime = chk ? chk.checked : !this._dateInsertShowTime;
        this._dateInsertRefresh();
    },
    dateInsertAdjust(unit, delta) {
        const d = this._dateInsertCurrent;
        if (!d) return;
        if (unit === 'year') { d.setFullYear(d.getFullYear() + delta); }
        else if (unit === 'month') { d.setMonth(d.getMonth() + delta); }
        else if (unit === 'day') { d.setDate(d.getDate() + delta); }
        else if (unit === 'hour') { d.setHours(d.getHours() + delta); }
        else if (unit === 'min') { d.setMinutes(d.getMinutes() + delta); }
        this._dateInsertRefresh();
    },
    _dateInsertRefresh() {
        const d = this._dateInsertCurrent;
        if (!d) return;
        const y = document.getElementById('date-insert-year');
        const m = document.getElementById('date-insert-month');
        const day = document.getElementById('date-insert-day');
        const h = document.getElementById('date-insert-hour');
        const min = document.getElementById('date-insert-min');
        const preview = document.getElementById('date-insert-preview');
        const timeRow = document.getElementById('date-insert-time-row');
        const showTime = this._dateInsertShowTime;
        if (timeRow) timeRow.style.display = showTime ? '' : 'none';
        if (y) y.textContent = d.getFullYear();
        if (m) m.textContent = d.getMonth() + 1;
        if (day) day.textContent = d.getDate();
        if (h) h.textContent = d.getHours();
        if (min) min.textContent = String(d.getMinutes()).padStart(2, '0');
        if (preview) preview.textContent = showTime ? formatDateTime(d) : (() => { const w = ['일','월','화','수','목','금','토'][d.getDay()]; return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}(${w})`; })();
    },
    insertDateFromPicker() {
        const ed = el('editor');
        if (!ed) return;
        const d = this._dateInsertCurrent || new Date();
        const dateStr = this._dateInsertShowTime ? formatDateTime(d) : (() => { const w = ['일','월','화','수','목','금','토'][d.getDay()]; return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}(${w})`; })();
        const pos = ed.selectionStart;
        const end = ed.selectionEnd;
        ed.setRangeText(dateStr, pos, end, 'end');
        ed.focus();
        US.snap(); TM.markDirty(); App.render();
        App.hideModal('date-insert-modal');
    },

    _toast(msg, duration) {
        let t = document.getElementById('app-toast');
        if (!t) { t = document.createElement('div'); t.id = 'app-toast'; document.body.appendChild(t); }
        t.style.whiteSpace = 'pre-line';
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(t._tid);
        t._tid = setTimeout(() => t.classList.remove('show'), duration || 2200);
    },
    hideModal(id) {
        if (id === 'image-modal') {
            const box = el('image-modal-box');
            if (box) box.classList.remove('img-modal-maximized');
            if (typeof clearImageModalTraces === 'function') clearImageModalTraces();
        }
        if (id === 'cite-modal') {
            const box = document.getElementById('cite-modal-box');
            if (box) box.classList.remove('cite-modal-maximized');
        }
        el(id).classList.remove('vis');
    },
    openColorPicker(m) { ColorPicker.open(m) },
    applyColor() { ColorPicker.apply() },
    showCaption(type) { CAP.show(type) },
    updateCapPreview() { CAP.updatePreview() },
    insertCaption() { CAP.insert() },
    showTmpl() { el('tmpl-modal').classList.add('vis') },
    insertTmpl(i) {
        const t = TMPLS[i];
        if (!confirm(`"${t.name}" 양식을 현재 문서에 추가하시겠습니까?`)) return;
        const edi = el('editor'); edi.value = (edi.value.trim() ? edi.value + '\n\n---\n\n' : '') + t.content;
        this.render(); US.snap(); App.hideModal('tmpl-modal');
    },
    insertSlideTmpl() {
        const style = parseInt(el('slide-tmpl-style').value, 10) || 1;
        const count = Math.max(1, Math.min(50, parseInt(el('slide-tmpl-count').value, 10) || 5));
        const parts = [];
        for (let i = 1; i <= count; i++) {
            const block = `# 제목${i}\n\n---\n\n- 내용`;
            parts.push(i < count ? block + '\n\n<div class="page-break"></div>' : block);
        }
        const content = parts.join('\n\n');
        const edi = el('editor');
        edi.value = (edi.value.trim() ? edi.value + '\n\n' : '') + content;
        PR.setSlideMode(true);
        const btn = document.getElementById('slide-mode-btn');
        if (btn) btn.classList.add('active');
        this.render(); US.snap(); App.hideModal('tmpl-modal');
    },

    toggleFind() {
        const bar = el('find-bar');
        const meBar = el('multi-edit-bar');
        if (meBar && meBar.classList.contains('vis')) meBar.classList.remove('vis');
        bar.classList.toggle('vis');
        if (bar.classList.contains('vis')) {
            const edi = el('editor');
            if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                const sel = edi.value.substring(edi.selectionStart, edi.selectionEnd);
                if (sel) el('fi').value = sel;
            }
            el('fi').focus();
            App._findStart = undefined;
            App.updateFindHighlight();
        } else {
            App.updateFindHighlight(true);
        }
    },

    /** 다중선택 편집 바: 선택 시 에디터에 span 삽입(PV에서 하이라이트), 닫을 때 span 제거 후 마무리 */
    _multiEditSpanStyle: 'background:#ffcc80',
    _multiEditSavedSelection: null,
    _ME_SPANMETHOD_KEY: 'mdpro_me_spanmethod',
    _multiEditUseSpan() { return localStorage.getItem(this._ME_SPANMETHOD_KEY) !== '0'; },
    _multiEditSaveSelection() {
        const edi = el('editor');
        if (!edi || edi.selectionStart === edi.selectionEnd) return;
        const start = edi.selectionStart, end = edi.selectionEnd;
        const text = edi.value.substring(start, end);
        if (!text) return;
        this._multiEditSavedSelection = { start, end, text: text.normalize('NFC') };
    },

    toggleMultiEditBar() {
        const meBar = el('multi-edit-bar');
        const findBar = el('find-bar');
        if (!meBar) return;
        if (meBar.classList.contains('vis')) {
            if (this._multiEditUseSpan()) this._multiEditStripSpans();
            meBar.classList.remove('vis');
            App.updateFindHighlight(true);
            US.snap();
            TM.markDirty();
            this.render();
            return;
        }
        if (findBar && findBar.classList.contains('vis')) findBar.classList.remove('vis');
        const edi = el('editor');
        const selEl = el('me-select');
        const repEl = el('me-replace');
        const useSpan = this._multiEditUseSpan();
        let sel = '';
        if (edi && document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
            sel = edi.value.substring(edi.selectionStart, edi.selectionEnd).normalize('NFC');
        }
        if (!sel && this._multiEditSavedSelection && edi) {
            const s = this._multiEditSavedSelection;
            const current = edi.value.substring(s.start, s.end);
            if (current === s.text) sel = s.text;
        }
        if (sel && selEl) {
            selEl.value = sel;
            if (useSpan && edi) {
                if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    const wrap = '<span style="' + this._multiEditSpanStyle + '">' + sel + '</span>';
                    edi.value = edi.value.split(sel).join(wrap);
                } else if (this._multiEditSavedSelection) {
                    const wrap = '<span style="' + this._multiEditSpanStyle + '">' + sel + '</span>';
                    edi.value = edi.value.substring(0, this._multiEditSavedSelection.start) + wrap + edi.value.substring(this._multiEditSavedSelection.end);
                }
            }
        }
        this._multiEditSavedSelection = null;
        if (repEl) repEl.value = (selEl && selEl.value) || '';
        meBar.classList.add('vis');
        App.updateFindHighlight();
        if (repEl) repEl.focus();
        US.snap();
        TM.markDirty();
        this.render();
    },

    _multiEditStripSpans() {
        const edi = el('editor');
        if (!edi) return;
        const style = this._multiEditSpanStyle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        edi.value = edi.value.replace(new RegExp('<span\\s+style="' + style + '">([\\s\\S]*?)<\\/span>', 'g'), '$1');
    },
    multiEditBarKey(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            App.multiEditApply();
            return;
        }
        if (e.key === 'Escape') {
            e.preventDefault();
            App.toggleMultiEditBar();
        }
    },
    multiEditApply() {
        const selEl = el('me-select');
        const repEl = el('me-replace');
        const edi = el('editor');
        if (!selEl || !repEl || !edi) return;
        const q = (selEl.value || '').normalize('NFC');
        const r = (repEl.value ?? '').normalize('NFC');
        if (!q) return;
        const useSpan = this._multiEditUseSpan();
        if (useSpan) {
            const needle = '<span style="' + this._multiEditSpanStyle + '">' + q + '</span>';
            const replacement = '<span style="' + this._multiEditSpanStyle + '">' + r + '</span>';
            const parts = edi.value.split(needle);
            const cnt = parts.length - 1;
            if (cnt <= 0) return;
            edi.value = parts.join(replacement);
            const cntEl = el('me-cnt');
            if (cntEl) cntEl.textContent = cnt + '건 교체됨';
        } else {
            const literal = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const re = new RegExp(literal, 'g');
            const cnt = (edi.value.match(re) || []).length;
            if (cnt === 0) return;
            edi.value = edi.value.replace(re, r);
            const cntEl = el('me-cnt');
            if (cntEl) cntEl.textContent = cnt + '건 교체됨';
        }
        selEl.value = r;
        repEl.value = r;
        US.snap();
        TM.markDirty();
        this.render();
        App.updateFindHighlight();
    },

    findKey(e) { if (e.key === 'Enter') e.shiftKey ? this.findPrev() : this.findNext(); if (e.key === 'Escape') this.toggleFind() },
    findNext() {
        const q = el('fi').value;
        if (!q) return;
        const edi = el('editor');
        const startFrom = (App._findStart != null) ? App._findStart : edi.selectionEnd;
        let idx = edi.value.indexOf(q, startFrom);
        if (idx === -1) idx = edi.value.indexOf(q);
        if (idx !== -1) {
            App._findStart = idx + q.length;
            edi.setSelectionRange(idx, idx + q.length);
            edi.focus();
        } else {
            App._findStart = undefined;
        }
        const cnt = (edi.value.match(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
        el('fc-cnt').textContent = cnt ? `${cnt}건` : q ? '없음' : '';
        App.updateFindHighlight();
    },
    findPrev() {
        const q = el('fi').value;
        if (!q) return;
        const edi = el('editor');
        const cursor = edi.selectionStart;
        const textBefore = edi.value.substring(0, cursor);
        let idx = textBefore.lastIndexOf(q);
        if (idx === -1) idx = edi.value.lastIndexOf(q);
        if (idx !== -1) {
            App._findStart = idx;
            edi.setSelectionRange(idx, idx + q.length);
            edi.focus();
        } else {
            App._findStart = undefined;
        }
        const cnt = (edi.value.match(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
        el('fc-cnt').textContent = cnt ? `${cnt}건` : q ? '없음' : '';
        App.updateFindHighlight();
    },
    replaceOne() { const q = el('fi').value, r = el('ri').value; if (!q) return; const edi = el('editor'), s = edi.selectionStart, e = edi.selectionEnd; if (edi.value.substring(s, e) === q) { edi.value = edi.value.substring(0, s) + r + edi.value.substring(e); App._findStart = s + r.length; this.render() } else this.findNext() },
    replaceAll() { const q = el('fi').value, r = el('ri').value; if (!q) return; const edi = el('editor'); const cnt = (edi.value.match(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length; edi.value = edi.value.replaceAll(q, r); this.render(); US.snap(); el('fc-cnt').textContent = `${cnt}건 교체됨`; App._findStart = undefined; App.updateFindHighlight() },

    updateFindHighlight(clear) {
        const bar = document.getElementById('find-bar');
        const meBar = document.getElementById('multi-edit-bar');
        const fi = document.getElementById('fi');
        const meSelect = document.getElementById('me-select');
        const layer = document.getElementById('editor-find-highlight');
        const edi = document.getElementById('editor');
        if (!layer || !edi) return;
        if (clear) {
            layer.innerHTML = '';
            layer.style.display = 'none';
            App._applyPreviewFindHighlight(el('preview-container'), '');
            return;
        }
        if (meBar && meBar.classList.contains('vis') && meSelect && meSelect.value.trim()) {
            const q = meSelect.value.trim();
            const cnt = (edi.value.split(q).length - 1);
            const cntEl = document.getElementById('me-cnt');
            if (cntEl) cntEl.textContent = cnt ? cnt + '건' : '없음';
            return;
        }
        if (!bar || !bar.classList.contains('vis') || !fi || !fi.value.trim()) {
            layer.innerHTML = '';
            layer.style.display = 'none';
            App._applyPreviewFindHighlight(el('preview-container'), '');
            return;
        }
        const q = fi.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(q, 'gi');
        const raw = edi.value;
        const selStart = edi.selectionStart, selEnd = edi.selectionEnd;
        let result = '', lastIndex = 0;
        let match;
        while ((match = re.exec(raw)) !== null) {
            const start = match.index, end = start + match[0].length;
            const escapedPrefix = raw.slice(lastIndex, start).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            const escapedMatch = match[0].replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            const isCurrent = (selStart === start && selEnd === end);
            result += escapedPrefix + (isCurrent ? '<mark class="find-current">' + escapedMatch + '</mark>' : '<mark>' + escapedMatch + '</mark>');
            lastIndex = end;
        }
        result += raw.slice(lastIndex).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        layer.innerHTML = result;
        layer.style.display = 'block';
        layer.scrollTop = edi.scrollTop;
        layer.scrollLeft = edi.scrollLeft;
        App._applyPreviewFindHighlight(el('preview-container'), fi.value.trim());
    },

    _applyPreviewFindHighlight(container, q) {
        if (!container) return;
        container.querySelectorAll('.find-highlight-pv').forEach(span => {
            const parent = span.parentNode;
            while (span.firstChild) parent.insertBefore(span.firstChild, span);
            parent.removeChild(span);
        });
        if (!q) return;
        const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null, false);
        const textNodes = [];
        let n;
        while ((n = walker.nextNode())) textNodes.push(n);
        textNodes.forEach(node => {
            const text = node.textContent;
            if (!text || text.trim() === '') return;
            re.lastIndex = 0;
            if (!re.test(text)) return;
            re.lastIndex = 0;
            const parts = [];
            let lastIndex = 0;
            let match;
            while ((match = re.exec(text)) !== null) {
                if (match.index > lastIndex) parts.push({ t: true, v: text.slice(lastIndex, match.index) });
                parts.push({ t: false, v: match[0] });
                lastIndex = match.index + match[0].length;
            }
            if (parts.length === 0) return;
            if (lastIndex < text.length) parts.push({ t: true, v: text.slice(lastIndex) });
            const frag = document.createDocumentFragment();
            parts.forEach(p => {
                if (p.t) frag.appendChild(document.createTextNode(p.v));
                else {
                    const span = document.createElement('span');
                    span.className = 'find-highlight-pv';
                    span.textContent = p.v;
                    frag.appendChild(span);
                }
            });
            node.parentNode.replaceChild(frag, node);
        });
    },

    saveMD() { const c = el('editor').value, t = el('doc-title').value.replace(/[^a-z0-9가-힣]/gi, '_'); dlBlob(c, `${t}.md`, 'text/markdown'); TM.markClean(); TM.persist(); this.hideModal('save-modal') },
    saveTXT() { const c = el('editor').value.replace(/[#*_`~>|]/g, '').replace(/\[(.*?)\]\(.*?\)/g, '$1').replace(/<[^>]+>/g, ''); dlBlob(c, (el('doc-title').value || 'document').replace(/[^a-z0-9가-힣]/gi, '_') + '.txt', 'text/plain;charset=utf-8'); TM.markClean(); TM.persist(); this.hideModal('save-modal') },
    saveHTML() {
        const md = el('editor').value; const title = el('doc-title').value;
        const showFn = el('show-footnotes-chk').checked;
        const pages = splitPages(md);
        const html = pages.map((p, i) => `<div class="preview-page${this.rm ? ' rm' : ''}" data-page="${i + 1}">${mdRender(p, showFn)}</div>`).join('');
        const CSS = `body{font-family:sans-serif;background:#6a6e7e;display:flex;flex-direction:column;align-items:center;padding:20px 0 40px}.preview-page{width:210mm;min-height:297mm;background:white;color:#1a1a2e;padding:22mm 18mm;box-shadow:0 4px 30px rgba(0,0,0,.4);font-family:'Libre Baskerville',Georgia,serif;font-size:11pt;line-height:1.8;word-break:break-word;position:relative;margin-bottom:20px}.preview-page::after{content:"— " attr(data-page) " —";position:absolute;bottom:10mm;left:50%;transform:translateX(-50%);font-family:sans-serif;font-size:9pt;color:#bbb}.preview-page h1{font-size:21pt;font-weight:700;margin:0 0 14px;border-bottom:2px solid #1a1a2e;padding-bottom:8px}.preview-page h2{font-size:15pt;margin:20px 0 10px;font-weight:700}.preview-page h3{font-size:12pt;margin:16px 0 7px;font-weight:700}.preview-page p{margin:0 0 11px}.preview-page ul,.preview-page ol{margin:0 0 11px;padding-left:22px}.preview-page table{width:100%;border-collapse:collapse;margin:11px 0;font-size:inherit}.preview-page th{background:#e8e8f0;color:#1a1a2e;padding:7px 11px;text-align:left;font-weight:600;border:1px solid #c0c0d8}.preview-page td{padding:6px 11px;border:1px solid #d0d0e0}.preview-page tr:nth-child(even) td{background:#f7f7fc}.preview-page code{font-family:monospace;font-size:9pt;background:#f0f0f8;padding:1px 4px;border-radius:3px;color:#5b4ce4}.preview-page pre{background:#1a1a2e;color:#e8e8f0;padding:14px;border-radius:6px;margin:11px 0;font-size:9pt}.preview-page pre code{background:none;color:inherit}.preview-page a{color:#5b4ce4}.preview-page img{max-width:100%}.preview-page .footnote-highlight{background:#f0f0f0;color:#1a1a2e;border-radius:2px;padding:0 2px}.preview-page .footnote-def{background:#f5f5f5;color:#1a1a2e;border-left:3px solid #bbb;padding:4px 10px;margin:4px 0;font-size:9.5pt}.preview-page .footnotes-section{border-top:1px solid #d0d0e0;margin-top:24px;padding-top:10px;font-size:9.5pt;color:#444}@media print{body{background:none;padding:0}.preview-page{box-shadow:none;margin:0;page-break-after:always;width:100%;min-height:0}.preview-page:last-child{page-break-after:auto}/* page number visible in print */.a4-rl,.a4-rl-label{display:none!important}}`;
        const fullHtml = `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>${title}</title><style>${CSS}</style></head><body>${html}</body></html>`;
        dlBlob(fullHtml, (el('doc-title').value || 'document').replace(/[^a-z0-9가-힣]/gi, '_') + '.html', 'text/html;charset=utf-8');
        TM.markClean(); TM.persist(); this.hideModal('save-modal');
    },
    printDoc() {
        const md = el('editor').value; const title = el('doc-title').value;
        const showFn = document.getElementById('show-footnotes-chk') ? el('show-footnotes-chk').checked : true;
        const pages = splitPages(md);
        const html = pages.map((p, i) => `<div class="preview-page${this.rm ? ' rm' : ''}" data-page="${i + 1}">${mdRender(p, showFn)}</div>`).join('');
        const CSS = `@import url('https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=JetBrains+Mono:wght@400;500&display=swap');*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#6a6e7e;display:flex;flex-direction:column;align-items:center;padding:20px 0 40px}.preview-page{width:210mm;min-height:297mm;background:white;color:#1a1a2e;padding:22mm 18mm;box-shadow:0 4px 30px rgba(0,0,0,.4);font-family:'Libre Baskerville',Georgia,serif;font-size:11pt;line-height:1.8;word-break:break-word;position:relative;margin-bottom:20px}.preview-page::after{content:"— " attr(data-page) " —";position:absolute;bottom:10mm;left:50%;transform:translateX(-50%);font-family:sans-serif;font-size:9pt;color:#bbb}.preview-page h1{font-size:21pt;font-weight:700;margin:0 0 14px;border-bottom:2px solid #1a1a2e;padding-bottom:8px}.preview-page h2{font-size:15pt;margin:20px 0 10px;font-weight:700}.preview-page h3{font-size:12pt;margin:16px 0 7px;font-weight:700}.preview-page p{margin:0 0 11px}.preview-page ul,.preview-page ol{margin:0 0 11px;padding-left:22px}.preview-page table{width:100%;border-collapse:collapse;margin:11px 0;font-size:inherit}.preview-page th{background:#e8e8f0;color:#1a1a2e;padding:7px 11px;text-align:left;font-weight:600;border:1px solid #c0c0d8}.preview-page td{padding:6px 11px;border:1px solid #d0d0e0}.preview-page tr:nth-child(even) td{background:#f7f7fc}.preview-page code{font-family:'JetBrains Mono',monospace;font-size:9pt;background:#f0f0f8;padding:1px 4px;border-radius:3px;color:#5b4ce4}.preview-page pre{background:#1a1a2e;color:#e8e8f0;padding:14px;border-radius:6px;margin:11px 0;font-size:9pt}.preview-page pre code{background:none;color:inherit}.preview-page img{max-width:100%}.preview-page a{color:#5b4ce4}.preview-page .footnote-highlight{background:#f0f0f0;color:#1a1a2e;border-radius:2px;padding:0 2px}.preview-page .footnote-def{background:#f5f5f5;color:#1a1a2e;border-left:3px solid #bbb;padding:4px 10px;margin:4px 0;font-size:9.5pt}.preview-page .footnotes-section{border-top:1px solid #d0d0e0;margin-top:24px;padding-top:10px;font-size:9.5pt;color:#444}@media print{body{background:none;padding:0}.preview-page{box-shadow:none;margin:0;page-break-after:always;width:100%;min-height:0}.preview-page:last-child{page-break-after:auto}/* page number visible in print */.a4-rl,.a4-rl-label{display:none!important}}`;
        const fullHtml = `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><title>${title}</title><style>${CSS}</style></head><body>${html}<script>window.onload=function(){window.print();}<\/script></body></html>`;
        const w = window.open('', '_blank', 'width=900,height=700');
        if (w) { w.document.open(); w.document.write(fullHtml); w.document.close(); }
        else { alert('팝업이 차단되었습니다. 팝업을 허용해 주세요.'); }
        this.hideModal('save-modal');
    },

    sample() {
        return `# Markdown PDF Editor Pro

**제작: 박중희(연세대 심리학과 겸임교수)**

- 논문 집필을 위한 에디터로 연구와 논문을 위한 도구입니다.
- 경기대학교 교육산업전공자
- 연세대학교 심리과학 이노베이션 대학원 심리트랙 전공자

## V20 업데이트 신기능

모든 기능이 통합된 **연구·논문 전용 에디터**입니다.

### 주요 기능 목록

| 기능 | 단축키 / 버튼 | 설명 |
| :-- | :-- | :-- |
| 코드 블록 (마지막 언어) | **Alt+C** | 마지막 사용 언어 즉시 삽입 |
| 코드 블록 (언어 선택) | ⌨ Code 버튼 | 언어 선택 모달 |
| 인용 삽입 | **Ctrl+Shift+C** | 참고문헌 관리자 |
| Research Mode | **Ctrl+Shift+R** | 단락 줄번호 표시 |
| 저장 | **Ctrl+S** | MD / TXT / HTML 선택 |
| **단축키 목록** | **Alt+/** | 단축키 표시 (편집 가능) |
| **표 HTML 정돈** | ✦ Tidy 버튼 | 병합 후 들여쓰기 정리 |
| **미리보기 복사** | 📋 복사 버튼 | 서식 있는 복사 (Word·구글독스) |
| **A4 구분선** | 📄 A4 버튼 | 297mm 위치에 빨간 점선 표시 |

---

### Research Mode 줄번호

**Ctrl+Shift+R** 또는 🔬 Research 버튼을 누르면 미리보기에서 각 단락에 줄번호가 표시됩니다.

이것은 두 번째 단락입니다. 줄번호가 왼쪽에 표시됩니다.

세 번째 단락입니다.

---

### 참고문헌 관리자

**📚 References** 버튼으로 APA 참고문헌을 붙여넣고 관리할 수 있습니다.

- **빈 줄 구분**: 여러 참고문헌을 빈 줄로 구분
- **엔터 구분**: 각 줄이 하나의 참고문헌

스타일 변환: APA → MLA 9 / Chicago / Vancouver 자동 변환을 지원합니다.

<div class="page-break"></div>

## 2페이지 — 캡션, 수식, 논문 양식

### 표 캡션 예시

<span class="tbl-caption"><표1> 연구대상 특성</span>

| 변수 | M | SD | n |
| :-- | :-- | :-- | :-- |
| 연령 | 24.5 | 3.2 | 120 |
| 학습시간 | 5.3 | 1.8 | 120 |

### 수식

$$
\\phi = \\frac{\\lambda_2}{c^2}
$$

### 논문 양식

**📋 양식** 버튼을 눌러 학위논문, SSCI/KCI, 단일/다중 연구, 메타분석 구조를 삽입하세요.

> \`Alt+/\` → 전체 단축키 목록
`}
};

/* ═══════════════════════════════════════════════════════════
   PWA — Service Worker + Manifest (인라인 생성)
   GitHub Pages 대응: blob: URL SW 미사용, scope 자동 감지
═══════════════════════════════════════════════════════════ */
(function () {
    // 1. Manifest 동적 생성 (blob: URL — 절대 URL 사용 시 start_url/scope 오류 감소)
    const origin = location.origin;
    const pathBase = location.pathname.replace(/[^/]*$/, '');
    const startPath = location.pathname || '/';
    const manifest = {
        name: 'Markdown PDF Editor Pro',
        short_name: 'MD PRO V20',
        description: '연구·논문 전용 마크다운 에디터',
        start_url: origin + startPath,
        scope: origin + pathBase,
        display: 'standalone',
        background_color: '#0f0f13',
        theme_color: '#1a1a24',
        icons: [
            { src: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="24" fill="%237c6af7"/><text x="96" y="130" font-size="110" text-anchor="middle" font-family="monospace" fill="white">M</text></svg>', sizes: '192x192', type: 'image/svg+xml' },
            { src: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="60" fill="%237c6af7"/><text x="256" y="360" font-size="300" text-anchor="middle" font-family="monospace" fill="white">M</text></svg>', sizes: '512x512', type: 'image/svg+xml' }
        ]
    };
    try {
        const blob = new Blob([JSON.stringify(manifest)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.getElementById('pwa-manifest');
        if (link) link.href = url;
    } catch(e) {}

    // 2. Service Worker — blob: URL은 GitHub Pages에서 scope 오류 발생
    //    → sw.js 파일이 있을 때만 등록 (http/https에서만, file:// 제외)
    if ('serviceWorker' in navigator && (location.protocol === 'http:' || location.protocol === 'https:')) {
        // 기존에 blob: URL로 등록된 SW가 있으면 해제 (구버전 호환)
        navigator.serviceWorker.getRegistrations().then(regs => {
            regs.forEach(reg => {
                if (reg.active && reg.active.scriptURL.startsWith('blob:')) {
                    reg.unregister();
                }
            });
        }).catch(() => {});

        // sw.js 파일이 배포 루트에 있을 때만 등록
        const swPath = location.pathname.replace(/[^/]*$/, '') + 'sw.js';
        fetch(swPath, { method: 'HEAD' }).then(r => {
            if (r.ok) {
                navigator.serviceWorker.register(swPath).catch(() => {});
            }
        }).catch(() => {});
    }
})();

window.addEventListener('DOMContentLoaded', () => {
    App.init();
    try { if (typeof FindHighlight !== 'undefined') FindHighlight.init(); } catch (e) {}
    try { if (typeof EditorSelection !== 'undefined') EditorSelection.init(); } catch (e) {}
    AiApiKey.load().catch(() => {});
    ScholarApiKey.load().catch(() => {});
    ScholarApiKey.initPasteExtract();
    /* 전역 날짜·시간 라이브 갱신 (잠금 버튼 앞 표시) */
    const dtEl = el('app-datetime');
    if (dtEl) {
        dtEl.textContent = formatDateTime();
        setInterval(() => { if (dtEl) dtEl.textContent = formatDateTime(); }, 1000);
    }
    /* 앱 종료 시 외부 PV 창도 함께 닫기 (보안) */
    function closePvOnExit() { if (typeof PW !== 'undefined' && PW.closeWin) PW.closeWin(); }
    window.addEventListener('beforeunload', closePvOnExit);
    window.addEventListener('pagehide', closePvOnExit);
    FM.restore().catch(e => console.warn('FM restore failed:', e));
    GH.restore().then(() => {
        /* 앱 열 때: 새 커밋 알람 + 기기 활동 확인 */
        GH.checkNewCommits().catch(() => {});
        GH.loadDeviceActivity().catch(() => {});
    }).catch(e => console.warn('GH restore failed:', e));
    /* 문자표 단축키 및 Shift+Alt 단축키 */
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'q') { e.preventDefault(); CharMap.show(); }
        if (e.shiftKey && e.altKey && (e.key === 'g' || e.key === 'G')) { e.preventDefault(); Translator.show(); }
        if (e.shiftKey && e.altKey && (e.key === 'm' || e.key === 'M')) { e.preventDefault(); SS.toggle(); }
        if (e.shiftKey && e.altKey && (e.key === 'a' || e.key === 'A')) { e.preventDefault(); if (typeof AuthorInfo !== 'undefined') AuthorInfo.insertIntoEditor(); }
        if (e.shiftKey && e.altKey && (e.key === 'd' || e.key === 'D')) { e.preventDefault(); App.insertDate(); }
    });

    /* ── gh-save-modal 리사이즈 드래그 ─────────────────── */
    (function initGhSaveResize() {
        const MIN_W = 400, MAX_W = Math.min(1200, window.innerWidth * 0.95);
        const MIN_H = 260;

        function makeResizable(handleEl, mode) {
            if (!handleEl) return;
            let startX, startY, startW, startH, boxEl;

            handleEl.addEventListener('mousedown', e => {
                boxEl = document.getElementById('gh-save-modal-box');
                if (!boxEl) return;
                e.preventDefault();
                startX = e.clientX;
                startY = e.clientY;
                startW = boxEl.offsetWidth;
                startH = boxEl.offsetHeight;

                function onMove(ev) {
                    const dX = ev.clientX - startX;
                    const dY = ev.clientY - startY;
                    if (mode === 'se' || mode === 'ew') {
                        const nw = Math.max(MIN_W, Math.min(MAX_W, startW + dX));
                        boxEl.style.width = nw + 'px';
                        boxEl.style.minWidth = nw + 'px';
                    }
                    if (mode === 'se') {
                        const nh = Math.max(MIN_H, startH + dY);
                        boxEl.style.maxHeight = nh + 'px';
                    }
                }
                function onUp() {
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                }
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            });
        }

        makeResizable(document.getElementById('gh-save-resize-handle'), 'se');
        makeResizable(document.getElementById('gh-save-resize-right'), 'ew');
    })();
});
/* ═══════════════════════════════════════════════════════════
   AI 질문 — Gemini 모델 선택 + 질문/답변 + thinking + 새 파일 삽입
═══════════════════════════════════════════════════════════ */
const DeepResearch = (() => {
    let _result = '';
    let _thinking = '';
    let _busy = false;
    let _newFileMode = false;
    let _currentTab = 'question';
    let _dragInit = false;
    let _abortController = null;
    const DB_NAME = 'mdlive-dr-history';
    const STORE_NAME = 'history';
    const PRE_PROMPT_KEY = 'mdpro_dr_pre_prompt';

    const $ = id => document.getElementById(id);

    function loadPrePrompt() {
        try {
            const raw = localStorage.getItem(PRE_PROMPT_KEY);
            const el = $('dr-pre-prompt');
            if (el) el.value = raw != null ? raw : '';
        } catch (e) {}
    }

    function savePrePrompt() {
        const el = $('dr-pre-prompt');
        const val = el ? el.value.trim() : '';
        try {
            localStorage.setItem(PRE_PROMPT_KEY, val);
            if (typeof App !== 'undefined' && App._toast) App._toast('사전 프롬프트 저장됨');
        } catch (e) {}
    }

    function _openDB() {
        return new Promise((resolve, reject) => {
            const r = indexedDB.open(DB_NAME, 1);
            r.onerror = () => reject(r.error);
            r.onsuccess = () => resolve(r.result);
            r.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    const s = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
                    s.createIndex('createdAt', 'createdAt', { unique: false });
                }
            };
        });
    }

    async function _getAll() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readonly');
            const store = t.objectStore(STORE_NAME);
            const req = store.getAll();
            req.onsuccess = () => {
                const raw = req.result || [];
                resolve(raw.filter(r => r.id !== '_historyOrder'));
            };
            req.onerror = () => reject(req.error);
        });
    }

    async function _getOrder() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readonly');
            const req = t.objectStore(STORE_NAME).get('_historyOrder');
            req.onsuccess = () => resolve(Array.isArray(req.result?.order) ? req.result.order : []);
            req.onerror = () => reject(req.error);
        });
    }

    async function _setOrder(orderIds) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).put({ id: '_historyOrder', order: orderIds });
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    async function _add(record) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).put(record);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    async function _delete(id) {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).delete(id);
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    function _renderHistoryList(items) {
        const list = $('dr-history-list');
        if (!list) return;
        list.textContent = '';
        list.removeAttribute('data-empty');
        if (!items.length) {
            list.setAttribute('data-empty', '질문 후 여기에 히스토리가 저장됩니다.');
            return;
        }
        items.forEach(item => {
            const row = document.createElement('div');
            row.className = 'dr-history-item';
            row.setAttribute('data-id', item.id);
            const title = document.createElement('span');
            title.className = 'dr-history-title';
            title.textContent = item.title || '(제목 없음)';
            const actions = document.createElement('span');
            actions.className = 'dr-history-actions';
            const renameBtn = document.createElement('button');
            renameBtn.type = 'button';
            renameBtn.className = 'btn-ic';
            renameBtn.title = '이름 변경';
            renameBtn.textContent = '✎';
            renameBtn.onclick = (e) => { e.stopPropagation(); DeepResearch.renameHistory(item.id); };
            const saveBtn = document.createElement('button');
            saveBtn.type = 'button';
            saveBtn.className = 'btn-ic';
            saveBtn.title = '이 항목만 .md 파일로 저장';
            saveBtn.textContent = '💾';
            saveBtn.onclick = (e) => { e.stopPropagation(); DeepResearch.saveHistoryItemToFile(item.id); };
            const delBtn = document.createElement('button');
            delBtn.type = 'button';
            delBtn.className = 'btn-ic';
            delBtn.title = '삭제';
            delBtn.textContent = '✕';
            delBtn.onclick = (e) => { e.stopPropagation(); DeepResearch.deleteHistory(item.id); };
            actions.append(renameBtn, saveBtn, delBtn);
            row.append(title, actions);
            row.onclick = () => DeepResearch.loadHistoryItem(item.id);
            list.appendChild(row);
        });
    }

    let _historyCache = [];
    let _historySearch = '';

    async function loadHistory() {
        try {
            const items = await _getAll();
            const orderIds = await _getOrder();
            const byId = new Map(items.map(it => [it.id, it]));
            const ordered = [];
            for (const id of orderIds) {
                if (byId.has(id)) {
                    ordered.push(byId.get(id));
                    byId.delete(id);
                }
            }
            const rest = [...byId.values()].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
            _historyCache = ordered.concat(rest);
        } catch (_) {
            _historyCache = [];
        }
        filterHistory(_historySearch);
    }

    function filterHistory(query) {
        _historySearch = (query || '').trim().toLowerCase();
        let list = _historyCache;
        if (_historySearch) {
            list = list.filter(item => {
                const t = (item.title || '').toLowerCase();
                const p = (item.prompt || '').toLowerCase();
                const r = (item.result || '').toLowerCase();
                return t.includes(_historySearch) || p.includes(_historySearch) || r.includes(_historySearch);
            });
        }
        _renderHistoryList(list);
    }

    async function loadHistoryItem(id) {
        const list = _historyCache.filter(x => x.id === id);
        const item = list[0];
        if (!item) return;
        const inp = $('dr-prompt'), out = $('dr-output'), thinkEl = $('dr-thinking'), thinkBtn = $('dr-thinking-btn'), insBtn = $('dr-insert-btn'), modelSel = $('dr-model');
        if (inp) inp.value = item.prompt || '';
        if (out) out.value = item.result || '';
        _result = item.result || '';
        _thinking = item.thinking || '';
        if (thinkEl) {
            thinkEl.value = item.thinking || '';
            const wrap = $('dr-thinking-wrap');
            if (wrap) wrap.style.display = item.thinking ? 'flex' : 'none';
            if (thinkEl) thinkEl.style.display = item.thinking ? 'flex' : 'none';
        }
        if (thinkBtn) thinkBtn.style.display = item.thinking ? '' : 'none';
        const copyThinkBtn = document.getElementById('dr-copy-thinking-btn');
        if (copyThinkBtn) copyThinkBtn.style.display = item.thinking ? '' : 'none';
        const translateThinkBtn = document.getElementById('dr-translate-thinking-btn');
        if (translateThinkBtn) translateThinkBtn.style.display = item.thinking ? '' : 'none';
        const openThinkBtn = document.getElementById('dr-open-thinking-btn');
        if (openThinkBtn) openThinkBtn.style.display = item.thinking ? '' : 'none';
        if (insBtn) insBtn.disabled = !(item.result && item.result.length > 0);
        if (modelSel && item.modelId) {
            modelSel.value = item.modelId;
        }
        switchTab('question');
    }

    function renameHistory(id) {
        const item = _historyCache.find(x => x.id === id);
        if (!item) return;
        const newTitle = prompt('파일명(제목)을 입력하세요. 검색에 사용됩니다.', item.title || '');
        if (newTitle == null || newTitle === '') return;
        const title = newTitle.trim() || item.title;
        const updated = { ...item, title };
        _add(updated).then(() => {
            const idx = _historyCache.findIndex(x => x.id === id);
            if (idx >= 0) _historyCache[idx] = updated;
            filterHistory(_historySearch);
        }).catch(() => alert('저장 실패'));
    }

    function deleteHistory(id) {
        if (!confirm('이 히스토리를 삭제할까요?')) return;
        _delete(id).then(async () => {
            const orderIds = await _getOrder();
            const next = orderIds.filter(x => x !== id);
            await _setOrder(next);
            _historyCache = _historyCache.filter(x => x.id !== id);
            filterHistory(_historySearch);
        }).catch(() => alert('삭제 실패'));
    }

    function _drSafeFilename(title) {
        const t = (title || '제목없음').trim() || '제목없음';
        return t.replace(/\.md$/i, '').replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').slice(0, 200) + '.md';
    }

    function openHistorySaveModal() {
        const modal = $('dr-history-save-modal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    function closeHistorySaveModal() {
        const modal = $('dr-history-save-modal');
        if (modal) modal.style.display = 'none';
    }

    function saveHistoryAsZip() {
        if (typeof JSZip === 'undefined') { alert('ZIP 라이브러리를 불러올 수 없습니다.'); return; }
        const items = _historyCache.filter(it => it.result && it.result.trim());
        if (!items.length) { alert('저장할 히스토리가 없습니다.'); return; }
        const zip = new JSZip();
        items.forEach((item, i) => {
            const name = _drSafeFilename(item.title || 'item-' + (i + 1));
            zip.file(name, item.result.trim(), { createFolders: false });
        });
        zip.generateAsync({ type: 'blob' }).then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'dr-history-' + (new Date().toISOString().slice(0, 10)) + '.zip';
            a.click();
            URL.revokeObjectURL(a.href);
        }).catch(() => alert('ZIP 생성 실패'));
    }

    function saveHistoryBatch() {
        const items = _historyCache.filter(it => it.result && it.result.trim());
        if (!items.length) { alert('저장할 히스토리가 없습니다.'); return; }
        items.forEach((item, i) => {
            setTimeout(() => {
                const name = _drSafeFilename(item.title || 'item-' + (i + 1));
                const blob = new Blob([item.result.trim()], { type: 'text/markdown;charset=utf-8' });
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = name;
                a.click();
                URL.revokeObjectURL(a.href);
            }, i * 150);
        });
        if (items.length > 0) alert(items.length + '개 파일이 다운로드됩니다. (브라우저 기본 저장 위치 확인)');
    }

    function saveHistoryItemToFile(id) {
        const item = _historyCache.find(x => x.id === id
            
        );
        if (!item || !item.result || !item.result.trim()) {
            alert('저장할 내용이 없습니다.');
            return;
        }
        const hasThinking = !!(item.thinking && item.thinking.trim());
        if (hasThinking) {
            _pendingThinkingMode = 'save';
            _pendingSaveId = id;
            const opts = document.getElementById('dr-thinking-insert-options');
            if (opts) opts.style.display = 'none';
            const chk = document.getElementById('dr-thinking-include-chk');
            const label = document.getElementById('dr-thinking-include-label');
            const btn = document.getElementById('dr-thinking-include-confirm-btn');
            const title = document.getElementById('dr-thinking-modal-title');
            if (chk) chk.checked = false;
            if (label) label.textContent = '생각 포함하여 저장';
            if (btn) btn.textContent = '저장';
            if (title) title.textContent = '저장 시 생각 포함';
            const modal = document.getElementById('dr-thinking-include-modal');
            if (modal) { modal.style.display = 'flex'; }
        } else {
            _doSaveHistoryItem(id, false);
        }
    }

    function _doSaveHistoryItem(id, includeThinking) {
        const item = _historyCache.find(x => x.id === id);
        if (!item || !item.result || !item.result.trim()) return;
        let content = item.result.trim();
        if (includeThinking && item.thinking && item.thinking.trim()) {
            content += '\n\n--- 생각 ---\n' + item.thinking.trim();
        }
        const name = _drSafeFilename(item.title);
        const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    let _pendingThinkingMode = null;
    let _pendingSaveId = null;

    function openThinkingIncludeModal(mode, id) {
        _pendingThinkingMode = mode;
        _pendingSaveId = id || null;
    }

    function closeThinkingIncludeModal() {
        const modal = document.getElementById('dr-thinking-include-modal');
        if (modal) modal.style.display = 'none';
        _pendingThinkingMode = null;
        _pendingSaveId = null;
    }

    function confirmThinkingInclude() {
        const chk = document.getElementById('dr-thinking-include-chk');
        const include = chk ? chk.checked : false;
        if (_pendingThinkingMode === 'save' && _pendingSaveId) {
            _doSaveHistoryItem(_pendingSaveId, include);
        } else if (_pendingThinkingMode === 'insert') {
            const belowRadio = document.getElementById('dr-thinking-insert-mode-below');
            const insertMode = (belowRadio && belowRadio.checked) ? 'below' : 'replace';
            _doInsert(include, insertMode);
        } else if (_pendingThinkingMode === 'newfile') {
            _doInsertToNewFile(include);
        }
        closeThinkingIncludeModal();
    }

    function switchTab(tab) {
        _currentTab = tab;
        const q = $('dr-panel-question'), p = $('dr-panel-pro'), a = $('dr-panel-ai-search'), d = $('dr-panel-data-research');
        const tabs = document.querySelectorAll('#dr-tabs .tr-tab');
        if (q) q.style.display = tab === 'question' ? 'flex' : 'none';
        if (p) p.style.display = tab === 'pro-preview' ? 'flex' : 'none';
        if (a) a.style.display = tab === 'ai-search' ? 'flex' : 'none';
        if (d) d.style.display = tab === 'data-research' ? 'flex' : 'none';
        tabs.forEach(t => {
            const active = t.getAttribute('data-tab') === tab;
            t.classList.toggle('active', active);
        });
        const inp = tab === 'question' ? $('dr-prompt') : tab === 'pro-preview' ? $('dr-prompt-pro') : tab === 'ai-search' ? $('dr-ai-prompt') : $('dr-data-prompt');
        if (inp) setTimeout(() => inp.focus(), 50);
        if (tab === 'ai-search') {
            const presetTa = $('dr-ai-preset-text');
            if (presetTa && !presetTa.value.trim()) applyAiSearchPreset();
        }
        if (tab === 'data-research') {
            const presetTa = $('dr-data-preset-text');
            if (presetTa && !presetTa.value.trim()) applyDataResearchPreset();
        }
    }

    function _initDraggable() {
        if (_dragInit) return;
        _dragInit = true;
        const box = $('dr-modal-box'), handle = document.querySelector('.dr-modal-drag');
        if (!box || !handle) return;
        let dx = 0, dy = 0, startX = 0, startY = 0;
        handle.addEventListener('mousedown', (e) => {
            if (e.button !== 0) return;
            if (box.classList.contains('dr-modal-maximized')) return;
            startX = e.clientX - dx;
            startY = e.clientY - dy;
            const onMove = (ev) => {
                dx = ev.clientX - startX;
                dy = ev.clientY - startY;
                box.style.transform = `translate(${dx}px, ${dy}px)`;
            };
            const onUp = () => {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            };
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    }

    function toggleMaximize() {
        const box = $('dr-modal-box');
        if (!box) return;
        const on = box.classList.toggle('dr-modal-maximized');
        box.style.transform = on ? '' : box.style.transform || '';
        if (!on) { box.style.transform = ''; }
        const btn = $('dr-maximize-btn');
        if (btn) btn.title = on ? '원래 크기' : '최대화';
    }

    async function _callApi(prompt, modelId, signal) {
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) throw new Error('AI API 키를 설정에서 입력·저장해 주세요.');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
        const body = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                temperature: 0.5,
                maxOutputTokens: 8192,
                ...(modelId.includes('2.5-pro') && { thinkingConfig: { includeThoughts: true } })
            }
        };
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: signal || AbortSignal.timeout(120000)
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error?.message || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const parts = d.candidates?.[0]?.content?.parts || [];
        let text = '';
        let thoughts = '';
        for (const p of parts) {
            const t = p.text || '';
            if (p.thought) thoughts += t;
            else text += t;
        }
        return { text: text.trim(), thoughts: thoughts.trim() };
    }

    function stopRun() {
        if (_abortController) _abortController.abort();
    }

    function show() {
        const modal = $('deep-research-modal');
        if (!modal) return;
        const box = $('dr-modal-box');
        if (box) {
            box.classList.remove('dr-modal-maximized');
            box.style.transform = '';
        }
        _initDraggable();
        switchTab('question');
        const ed = $('editor');
        if (ed) {
            const sel = ed.value.substring(ed.selectionStart, ed.selectionEnd).trim();
            if (sel) {
                const inp = $('dr-prompt');
                if (inp) inp.value = sel;
            }
        }
        modal.classList.add('vis');
        _newFileMode = false;
        const hint = $('dr-insert-hint');
        if (hint) hint.textContent = '새파일로 삽입';
        loadPrePrompt();
        loadHistory();
        setTimeout(() => { const inp = $('dr-prompt'); if (inp) inp.focus(); }, 60);
    }

    function hide() {
        const m = $('deep-research-modal');
        if (m) m.classList.remove('vis');
    }

    async function run() {
        if (_busy) return;
        const inp = $('dr-prompt'), out = $('dr-output'), thinkEl = $('dr-thinking');
        const loadEl = $('dr-loading'), thinkBtn = $('dr-thinking-btn'), insBtn = $('dr-insert-btn'), stopBtn = $('dr-stop-btn');
        let prompt = inp ? inp.value.trim() : '';
        if (!prompt) { alert('질문을 입력해 주세요.'); return; }
        const preEl = $('dr-pre-prompt');
        const prePrompt = preEl ? preEl.value.trim() : '';
        if (prePrompt) prompt = prePrompt + '\n\n' + prompt;
        prompt += _getStyleInstruction();
        const modelId = $('dr-model')?.value || 'gemini-2.5-pro';

        _busy = true;
        _abortController = new AbortController();
        const timeoutId = setTimeout(() => { if (_abortController) _abortController.abort(); }, 120000);
        if (loadEl) loadEl.style.display = 'flex';
        if (stopBtn) stopBtn.style.display = '';
        if (out) out.value = '답변 생성 중…';
        if (thinkEl) { thinkEl.value = ''; thinkEl.style.display = 'none'; }
        const drThinkingWrap = $('dr-thinking-wrap');
        if (drThinkingWrap) drThinkingWrap.style.display = 'none';
        if (thinkBtn) thinkBtn.style.display = 'none';
        const copyThinkBtn0 = document.getElementById('dr-copy-thinking-btn');
        if (copyThinkBtn0) copyThinkBtn0.style.display = 'none';
        const translateThinkBtn0 = document.getElementById('dr-translate-thinking-btn');
        if (translateThinkBtn0) translateThinkBtn0.style.display = 'none';
        const openThinkBtn0 = document.getElementById('dr-open-thinking-btn');
        if (openThinkBtn0) openThinkBtn0.style.display = 'none';
        if (insBtn) insBtn.disabled = true;

        try {
            const { text, thoughts } = await _callApi(prompt, modelId, _abortController.signal);
            _result = text;
            _thinking = thoughts;
            if (out) out.value = text || '(결과 없음)';
            if (thinkEl) thinkEl.value = thoughts;
            const drWrap = $('dr-thinking-wrap');
            if (drWrap) drWrap.style.display = thoughts ? 'flex' : 'none';
            if (thinkEl) thinkEl.style.display = thoughts ? 'flex' : 'none';
            if (thinkBtn) thinkBtn.style.display = thoughts ? '' : 'none';
            const copyThinkBtn = document.getElementById('dr-copy-thinking-btn');
            if (copyThinkBtn) copyThinkBtn.style.display = thoughts ? '' : 'none';
            const translateThinkBtn = document.getElementById('dr-translate-thinking-btn');
            if (translateThinkBtn) translateThinkBtn.style.display = thoughts ? '' : 'none';
            const openThinkBtn = document.getElementById('dr-open-thinking-btn');
            if (openThinkBtn) openThinkBtn.style.display = thoughts ? '' : 'none';
            if (insBtn) insBtn.disabled = !text;
            const title = prompt.slice(0, 50).trim() + (prompt.length > 50 ? '…' : '');
            const record = {
                id: 'dr-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
                title,
                prompt,
                result: text || '',
                thinking: thoughts || '',
                modelId,
                createdAt: Date.now()
            };
            await _add(record);
            const orderIds = await _getOrder();
            orderIds.unshift(record.id);
            await _setOrder(orderIds);
            _historyCache.unshift(record);
            filterHistory(_historySearch);
        } catch (e) {
            _result = '';
            _thinking = '';
            if (e.name === 'AbortError') {
                if (out) out.value = '⏹ 진행이 중지되었습니다.';
            } else {
                if (out) out.value = '⚠ ' + (e.message || String(e));
            }
            if (thinkBtn) thinkBtn.style.display = 'none';
            const wrapErr = $('dr-thinking-wrap');
            if (wrapErr) wrapErr.style.display = 'none';
            const copyThinkBtnErr = document.getElementById('dr-copy-thinking-btn');
            if (copyThinkBtnErr) copyThinkBtnErr.style.display = 'none';
            const translateThinkBtnErr = document.getElementById('dr-translate-thinking-btn');
            if (translateThinkBtnErr) translateThinkBtnErr.style.display = 'none';
            const openThinkBtnErr = document.getElementById('dr-open-thinking-btn');
            if (openThinkBtnErr) openThinkBtnErr.style.display = 'none';
            if (insBtn) insBtn.disabled = true;
        } finally {
            _busy = false;
            _abortController = null;
            clearTimeout(timeoutId);
            if (loadEl) loadEl.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'none';
        }
    }

    async function runPro() {
        const inp = $('dr-prompt-pro'), out = $('dr-output'), insBtn = $('dr-insert-btn');
        const prompt = inp ? inp.value.trim() : '';
        if (!prompt) { alert('리서치 질문을 입력해 주세요.'); return; }
        out.value = '⏳ Deep Research Pro Preview (deep-research-pro-preview-12-2025)는 Interactions API를 사용하며, 현재 서비스 준비 중입니다.';
        _result = out.value;
        if (insBtn) insBtn.disabled = false;
    }

    function toggleThinking() {
        const wrap = $('dr-thinking-wrap'), thinkEl = $('dr-thinking'), btn = $('dr-thinking-btn');
        if (!wrap || !btn) return;
        const show = wrap.style.display !== 'flex';
        wrap.style.display = show ? 'flex' : 'none';
        if (thinkEl) thinkEl.style.display = show ? 'flex' : 'none';
        btn.textContent = show ? '💭 생각 숨기기' : '💭 생각';
    }

    function _drFixedFilename() {
        const d = new Date();
        const y = d.getFullYear(), m = String(d.getMonth() + 1).padStart(2, '0'), day = String(d.getDate()).padStart(2, '0');
        const h = String(d.getHours()).padStart(2, '0'), min = String(d.getMinutes()).padStart(2, '0');
        return `dr-${y}-${m}-${day}-${h}${min}`;
    }

    function insertToNewFile() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) {
            alert('삽입할 답변이 없습니다. 먼저 질문을 실행해 주세요.');
            return;
        }
        if (typeof TM === 'undefined') {
            alert('탭 기능을 사용할 수 없습니다.');
            return;
        }
        const hasThinking = !!(_thinking && _thinking.trim());
        if (hasThinking) {
            _pendingThinkingMode = 'newfile';
            _pendingSaveId = null;
            const opts = document.getElementById('dr-thinking-insert-options');
            if (opts) opts.style.display = 'none';
            const chk = document.getElementById('dr-thinking-include-chk');
            const label = document.getElementById('dr-thinking-include-label');
            const btn = document.getElementById('dr-thinking-include-confirm-btn');
            const title = document.getElementById('dr-thinking-modal-title');
            if (chk) chk.checked = false;
            if (label) label.textContent = '생각 포함하여 새 파일로 삽입';
            if (btn) btn.textContent = '새 파일로 삽입';
            if (title) title.textContent = '새 파일로 삽입 시 생각 포함';
            const modal = document.getElementById('dr-thinking-include-modal');
            if (modal) modal.style.display = 'flex';
        } else {
            _doInsertToNewFile(false);
        }
    }

    function _doInsertToNewFile(includeThinking) {
        const out = $('dr-output');
        let txt = out ? out.value.trim() : _result;
        if (!txt) return;
        if (includeThinking && _thinking && _thinking.trim()) {
            txt = txt + '\n\n--- 생각 ---\n' + _thinking.trim();
        }
        const hintEl = $('dr-insert-hint');
        const customName = hintEl && hintEl.value ? hintEl.value.trim() : '';
        const name = customName !== '' ? customName.replace(/\.md$/i, '') : _drFixedFilename();
        TM.newTab(name, txt, 'md');
        hide();
    }

    function toggleNewFile() {
        _newFileMode = !_newFileMode;
        const fn = $('dr-filename'), hint = $('dr-insert-hint');
        if (fn) fn.style.display = _newFileMode ? 'inline-block' : 'none';
        if (hint) hint.textContent = '새파일로 삽입';
        if (_newFileMode && fn) fn.focus();
    }

    function insert() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) return;

        const hasThinking = !!(_thinking && _thinking.trim());
        if (hasThinking) {
            _pendingThinkingMode = 'insert';
            _pendingSaveId = null;
            const opts = document.getElementById('dr-thinking-insert-options');
            if (opts) opts.style.display = 'block';
            const replaceRadio = document.getElementById('dr-thinking-insert-mode-replace');
            if (replaceRadio) replaceRadio.checked = true;
            const chk = document.getElementById('dr-thinking-include-chk');
            const label = document.getElementById('dr-thinking-include-label');
            const btn = document.getElementById('dr-thinking-include-confirm-btn');
            const title = document.getElementById('dr-thinking-modal-title');
            if (chk) chk.checked = false;
            if (label) label.textContent = '생각 포함하여 삽입';
            if (btn) btn.textContent = '삽입';
            if (title) title.textContent = '삽입 시 생각 포함';
            const modal = document.getElementById('dr-thinking-include-modal');
            if (modal) modal.style.display = 'flex';
        } else {
            _doInsert(false);
        }
    }

    function _doInsert(includeThinking, insertMode) {
        const out = $('dr-output');
        let txt = out ? out.value.trim() : _result;
        if (!txt) return;
        if (includeThinking && _thinking && _thinking.trim()) {
            txt = txt + '\n\n--- 생각 ---\n' + _thinking.trim();
        }
        const ed = $('editor');
        if (!ed) return;
        const val = ed.value;
        const s = ed.selectionStart, e2 = ed.selectionEnd;

        if (insertMode === 'below') {
            const from = e2;
            const lineEndIdx = val.indexOf('\n', from);
            const insertAt = lineEndIdx === -1 ? val.length : lineEndIdx + 1;
            const needNewline = (insertAt > 0 && val[insertAt - 1] !== '\n') || (insertAt === val.length && val.length > 0 && val[val.length - 1] !== '\n');
            ed.setRangeText(needNewline ? '\n' + txt : txt, insertAt, insertAt, 'end');
        } else {
            ed.setRangeText(txt, s, e2, 'end');
        }
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        hide();
    }

    function copyResult() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) return;
        navigator.clipboard.writeText(txt).then(() => alert('복사되었습니다.')).catch(() => {});
    }

    function clearOutput() {
        const out = $('dr-output');
        if (out) out.value = '';
        _result = '';
        const insBtn = $('dr-insert-btn');
        if (insBtn) insBtn.disabled = true;
    }

    function copyThinking() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) {
            alert('복사할 생각 내용이 없습니다.');
            return;
        }
        navigator.clipboard.writeText(txt).then(() => alert('생각 내용이 복사되었습니다.')).catch(() => {});
    }

    function openThinkingInNewWindow() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) {
            alert('표시할 생각 내용이 없습니다.');
            return;
        }
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(txt, true) : (typeof marked !== 'undefined' ? marked.parse(txt) : txt.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:red">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=900,height=700,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>생각 미리보기</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body class="dr-pv-window" style="margin:0;background:var(--bg1)">' +
            '<div id="preview-container" class="preview-container" style="position:absolute;inset:0;overflow:auto;padding:24px;box-sizing:border-box">' +
            '<div class="preview-page" data-page="1">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    function openResultForTranslate() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) { alert('번역할 결과가 없습니다.'); return; }
        hide();
        if (typeof Translator !== 'undefined') Translator.show(txt);
    }

    function openThinkingForTranslate() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('번역할 생각 내용이 없습니다.'); return; }
        hide();
        if (typeof Translator !== 'undefined') Translator.show(txt);
    }

    /** 텍스트가 주로 한국어면 ko→en, 아니면 en→ko. (en/ko 간단용) */
    function _drDetectEnKo(text) {
        if (!text || !text.length) return { sl: 'en', tl: 'ko' };
        let koCount = 0;
        for (let i = 0; i < text.length; i++) {
            const c = text.charCodeAt(i);
            if ((c >= 0xAC00 && c <= 0xD7A3) || (c >= 0x1100 && c <= 0x11FF) || (c >= 0x3130 && c <= 0x318F)) koCount++;
        }
        const ratio = koCount / text.length;
        return ratio > 0.15 ? { sl: 'ko', tl: 'en' } : { sl: 'en', tl: 'ko' };
    }

    /** #dr-thinking 안 툴바: 구글번역기 (en↔ko). 구글 스크래핑 없이 탭만 연다. */
    function thinkingTranslateGoogle() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('생각 내용이 없습니다.'); return; }
        if (typeof Translator === 'undefined') return;
        const { sl, tl } = _drDetectEnKo(txt);
        Translator.openBrowserWithText(txt, sl, tl);
    }

    /** #dr-thinking 안 툴바: 구글 스크래핑으로 번역 후 번역만 새창 (en↔ko). */
    function thinkingTranslateResultNewWindow() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('생각 내용이 없습니다.'); return; }
        if (typeof Translator === 'undefined') return;
        const { sl, tl } = _drDetectEnKo(txt);
        Translator.translateText(txt, sl, tl)
            .then(trans => Translator.openTranslationInNewWindowWithText(trans))
            .catch(e => alert('번역 실패: ' + (e.message || e)));
    }

    /** #dr-thinking 안 툴바: 구글 스크래핑으로 번역 후 원문+번역 새창 (en↔ko). */
    function thinkingTranslateBothNewWindow() {
        const el = $('dr-thinking');
        const txt = el ? el.value.trim() : _thinking || '';
        if (!txt) { alert('생각 내용이 없습니다.'); return; }
        if (typeof Translator === 'undefined') return;
        const { sl, tl } = _drDetectEnKo(txt);
        Translator.translateText(txt, sl, tl)
            .then(trans => Translator.openOriginalAndTranslationInNewWindowWithText(txt, trans))
            .catch(e => alert('번역 실패: ' + (e.message || e)));
    }

    function openResultInNewWindow() {
        const out = $('dr-output');
        const txt = out ? out.value.trim() : _result;
        if (!txt) {
            alert('표시할 답변이 없습니다.');
            return;
        }
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(txt, true) : (typeof marked !== 'undefined' ? marked.parse(txt) : txt.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:red">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=900,height=700,scrollbars=yes,resizable=yes');
        if (!w) {
            alert('팝업이 차단되었을 수 있습니다. 새 창 허용 후 다시 시도해 주세요.');
            return;
        }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>답변 미리보기</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body class="dr-pv-window" style="margin:0;background:var(--bg1)">' +
            '<div id="preview-container" class="preview-container" style="position:absolute;inset:0;overflow:auto;padding:24px;box-sizing:border-box">' +
            '<div class="preview-page" data-page="1">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    async function runCiteAiSearch() {
        const presetEl = $('dr-ai-preset-text');
        const topicEl = $('dr-ai-topic');
        const yearsEl = $('dr-ai-years');
        const questionEl = $('dr-ai-prompt');
        const out = $('dr-output');
        const modelEl = $('dr-ai-model');
        if (!presetEl || !out) return;
        let prompt = (presetEl.value || '').trim();
        const topic = (topicEl && topicEl.value) ? topicEl.value.trim() : '';
        const years = (yearsEl && yearsEl.value) ? yearsEl.value.trim() : '';
        const question = (questionEl && questionEl.value) ? questionEl.value.trim() : '';
        if (!prompt) { out.value = '사전 프롬프트를 선택하거나 입력하세요.'; return; }
        prompt = prompt
            .replace(/\[여기에 주제 입력\]/g, topic || '[주제 미입력]')
            .replace(/\[연도 범위 입력\]/g, years || '[연도 미입력]')
            .replace(/\[연구주제\]/g, topic || '[주제 미입력]')
            .replace(/\[주제\]/g, topic || '[주제 미입력]');
        prompt += '\n\n' + _AI_SEARCH_VERIFICATION;
        if (question) prompt += '\n\n질문:\n' + question;
        prompt += _getStyleInstruction();
        const modelId = (modelEl && modelEl.value) ? modelEl.value : 'gemini-3-flash-preview';
        out.value = '🔄 AI 검색 중...';
        try {
            const { text } = await _callApi(prompt, modelId);
            out.value = text || '(결과 없음)';
        } catch (e) {
            out.value = '❌ ' + (e.message || String(e));
        }
    }

    function _getStyleInstruction() {
        const el = $('dr-style-tone');
        if (!el || !el.value) return '';
        const v = el.value;
        if (v === 'academic') return '\n\n답변은 반드시 학술체(~이다)로 작성하세요.';
        if (v === 'report') return '\n\n답변은 반드시 보고체(~임, ~함)로 작성하세요.';
        if (v === 'polite') return '\n\n답변은 반드시 일반체(존댓말)로 작성하세요.';
        return '';
    }

    async function runDataResearch() {
        const presetEl = $('dr-data-preset-text');
        const questionEl = $('dr-data-prompt');
        const out = $('dr-output');
        const modelEl = $('dr-data-model');
        if (!presetEl || !out) return;
        let prompt = (presetEl.value || '').trim();
        const question = (questionEl && questionEl.value) ? questionEl.value.trim() : '';
        if (!prompt) { out.value = '사전 프롬프트를 선택하거나 입력하세요.'; return; }
        prompt = prompt
            .replace(/\[여기에 주제 입력\]/g, question || '[주제 미입력]')
            .replace(/\[여기에 구체적 주제 입력\]/g, question || '[주제 미입력]')
            .replace(/\[연도 범위 입력\]/g, '[연도 범위 입력]')
            .replace(/\[연구주제\]/g, question || '[주제 미입력]')
            .replace(/\[주제\]/g, question || '[주제 미입력]');
        prompt += '\n\n' + _AI_SEARCH_VERIFICATION;
        if (question) prompt += '\n\n질문:\n' + question;
        prompt += _getStyleInstruction();
        const modelId = (modelEl && modelEl.value) ? modelEl.value : 'gemini-3-flash-preview';
        out.value = '🔄 AI자료조사 중...';
        try {
            const { text } = await _callApi(prompt, modelId);
            out.value = text || '(결과 없음)';
        } catch (e) {
            out.value = '❌ ' + (e.message || String(e));
        }
    }

    function applyDataResearchPreset() {
        const sel = $('dr-data-preset');
        const ta = $('dr-data-preset-text');
        if (!sel || !ta) return;
        const key = sel.value || 'basic';
        ta.value = _AI_SEARCH_PRESETS[key] || _AI_SEARCH_PRESETS.basic;
    }

    function openDataPresetTextWindow() {
        const ta = $('dr-data-preset-text');
        if (!ta) return;
        window.__drDataPresetApply = function(popupWin) {
            try {
                const pw = popupWin.document.getElementById('pw');
                if (pw) ta.value = pw.value;
            } catch (e) {}
            popupWin.close();
        };
        window.__drDataPresetText = function() { return ta ? ta.value : ''; };
        _openPresetWindowWithTools('__drDataPresetApply', '__drDataPresetText');
    }

    function _openPresetWindowWithTools(applyKey, getTextKey) {
        const w = window.open('', '_blank', 'width=720,height=520,resizable=yes,scrollbars=yes');
        if (!w) return;
        const applyQ = JSON.stringify(applyKey);
        const getQ = JSON.stringify(getTextKey);
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>사전 프롬프트</title><style>'
            + 'body{font-family:inherit;background:#1c1c26;color:#e8e8f0;margin:0;padding:12px;box-sizing:border-box;display:flex;flex-direction:column;height:100%;}'
            + '#pw-wrap{flex:1;min-height:0;overflow:auto;}'
            + 'textarea{width:100%;height:100%;min-height:280px;background:#16161d;border:1px solid #2e2e42;color:#e8e8f0;padding:10px;font-size:13px;line-height:1.5;resize:both;display:block;box-sizing:border-box;}'
            + '.btns{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;flex-shrink:0;}'
            + 'button{padding:6px 12px;cursor:pointer;border-radius:4px;font-size:12px;}'
            + '.apply{background:#7c6af7;color:#fff;border:none;}'
            + '.close{background:#2a2a3a;color:#9090b0;border:1px solid #2e2e42;}'
            + '.tool{background:#3a3a4a;color:#c0c0e0;border:1px solid #2e2e42;}'
            + '</style></head><body>'
            + '<div id="pw-wrap"><textarea id="pw"></textarea></div>'
            + '<div class="btns">'
            + '<button class="tool" onclick="var t=document.getElementById(\'pw\');var s=parseInt(getComputedStyle(t).fontSize)||13;t.style.fontSize=Math.min(24,s+2)+\'px\'">확대</button>'
            + '<button class="tool" onclick="var t=document.getElementById(\'pw\');var s=parseInt(getComputedStyle(t).fontSize)||13;t.style.fontSize=Math.max(10,s-2)+\'px\'">축소</button>'
            + '<button class="tool" onclick="document.getElementById(\'pw-wrap\').scrollTop=0">맨 위로</button>'
            + '<button class="tool" onclick="window.print()">인쇄</button>'
            + '<button class="apply" onclick="opener[' + applyQ + '](window)">적용 후 닫기</button>'
            + '<button class="close" onclick="window.close()">닫기</button>'
            + '</div>'
            + '<script>document.getElementById("pw").value=opener[' + getQ + ']();<\/script></body></html>'
        );
        w.document.close();
    }

    function openPresetTextWindow() {
        const ta = $('dr-ai-preset-text');
        if (!ta) return;
        window.__drPresetApply = function(popupWin) {
            try {
                const pw = popupWin.document.getElementById('pw');
                if (pw) ta.value = pw.value;
            } catch (e) {}
            popupWin.close();
        };
        window.__drPresetText = function() { return ta ? ta.value : ''; };
        _openPresetWindowWithTools('__drPresetApply', '__drPresetText');
    }

    function applyCiteAiSearchPreset() {
        const sel = document.getElementById('cite-ai-preset');
        const ta = document.getElementById('cite-ai-preset-text');
        if (!sel || !ta) return;
        const key = sel.value || 'basic';
        ta.value = _AI_SEARCH_PRESETS[key] || _AI_SEARCH_PRESETS.basic;
    }

    function openCitePresetTextWindow() {
        const ta = document.getElementById('cite-ai-preset-text');
        if (!ta) return;
        window.__citePresetApply = function(popupWin) {
            try {
                const pw = popupWin.document.getElementById('pw');
                if (pw) ta.value = pw.value;
            } catch (e) {}
            popupWin.close();
        };
        window.__citePresetText = function() { return ta ? ta.value : ''; };
        _openPresetWindowWithTools('__citePresetApply', '__citePresetText');
    }

    async function runCiteAiSearchFromModal() {
        const presetEl = document.getElementById('cite-ai-preset-text');
        const questionEl = document.getElementById('cite-ai-prompt');
        const out = document.getElementById('cite-ai-out');
        const modelEl = document.getElementById('cite-ai-model');
        if (!presetEl || !out) return;
        let prompt = (presetEl.value || '').trim();
        const question = (questionEl && questionEl.value) ? questionEl.value.trim() : '';
        if (!prompt) { out.value = '사전 프롬프트를 선택하거나 입력하세요.'; return; }
        prompt = prompt
            .replace(/\[여기에 주제 입력\]/g, '[주제 미입력]')
            .replace(/\[연도 범위 입력\]/g, '[연도 미입력]')
            .replace(/\[연구주제\]/g, '[주제 미입력]')
            .replace(/\[주제\]/g, '[주제 미입력]');
        prompt += '\n\n' + _AI_SEARCH_VERIFICATION;
        if (question) prompt += '\n\n질문:\n' + question;
        prompt += _getStyleInstruction();
        const modelId = (modelEl && modelEl.value) ? modelEl.value : 'gemini-3-flash-preview';
        out.value = '🔄 AI 검색 중...';
        try {
            const { text } = await _callApi(prompt, modelId);
            out.value = text || '(결과 없음)';
        } catch (e) {
            out.value = '❌ ' + (e.message || String(e));
        }
    }

    function _getCiteModalOutText() {
        const out = document.getElementById('cite-ai-out');
        return out ? out.value.trim() : '';
    }

    function insertFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('삽입할 답변이 없습니다.'); return; }
        const ed = document.getElementById('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(txt, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        if (typeof App !== 'undefined') App.hideModal('cite-modal');
    }

    function insertToNewFileFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('삽입할 답변이 없습니다.'); return; }
        if (typeof TM === 'undefined') { alert('탭 기능을 사용할 수 없습니다.'); return; }
        const hintEl = document.getElementById('cite-ai-insert-hint');
        const customName = hintEl && hintEl.value ? hintEl.value.trim() : '';
        const name = customName || _drFixedFilename();
        TM.newTab(name, txt);
        if (hintEl) hintEl.value = '';
        if (typeof App !== 'undefined') App.hideModal('cite-modal');
    }

    function copyResultFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('복사할 결과가 없습니다.'); return; }
        navigator.clipboard.writeText(txt).then(() => alert('복사되었습니다.')).catch(() => {});
    }

    function openResultInNewWindowFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('표시할 답변이 없습니다.'); return; }
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(txt, true) : (typeof marked !== 'undefined' ? marked.parse(txt) : txt.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:red">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=900,height=700,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>답변 미리보기</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body class="dr-pv-window" style="margin:0;background:var(--bg1)">' +
            '<div id="preview-container" class="preview-container" style="position:absolute;inset:0;overflow:auto;padding:24px;box-sizing:border-box">' +
            '<div class="preview-page" data-page="1">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    function openResultForTranslateFromCiteModal() {
        const txt = _getCiteModalOutText();
        if (!txt) { alert('번역할 결과가 없습니다.'); return; }
        if (typeof App !== 'undefined') App.hideModal('cite-modal');
        if (typeof Translator !== 'undefined') Translator.show(txt);
    }

    const _AI_SEARCH_PRESETS = {
        basic: `You are an academic research assistant.

Task:
Search for real, peer-reviewed journal articles on the following topic:
[여기에 주제 입력]

Search conditions:
- Publication years: [연도 범위 입력]
- Only include verifiable, existing journal articles.
- Do NOT fabricate citations.
- If bibliographic information is uncertain, explicitly state uncertainty.

Output requirements:
1. Format all references strictly in APA 7th edition.
2. Include DOI when available.
3. Indicate journal indexing status (SSCI/SCIE/ESCI/Scopus if known).
4. Separate domestic (Korean) and international studies if applicable.
5. For each article, provide 2–3 sentences summarizing:
   - Research purpose
   - Methodology (e.g., SEM, multilevel modeling, regression, meta-analysis)
   - Key findings
6. Focus on recent theoretical frameworks when relevant.`,
        research: `You are a doctoral-level research assistant.

Search for empirical studies on:
[연구주제]

Conditions:
- Years: 2023–2026
- Empirical quantitative studies only
- Clearly state:
    - Theoretical framework (e.g., Meyer & Allen model, JD-R model, SET)
    - Sample size and characteristics
    - Statistical method used (SEM, PLS-SEM, multilevel SEM, HLM, CFA, regression)
    - Model fit indices if SEM is used
- Provide citation count if available.
- APA 7 format with DOI required.
- No fabricated sources.`,
        meta: `Search for systematic reviews or meta-analyses on:
[주제]

Include:
- Effect sizes reported
- Number of studies included
- Statistical model used (random/fixed effects)
- Publication bias test methods
- DOI and APA 7 format

Exclude narrative reviews.`,
        recommend: `You are an academic research assistant.

Search for peer-reviewed empirical journal articles on:
[주제]

Years: 2023–2026

Requirements:
- Only real, verifiable articles.
- Verify existence through academic databases.
- APA 7th edition format.
- DOI required.
- State theoretical framework.
- Specify statistical method.
- Separate Korean and international studies.
- Provide 2–3 sentence structured summary.
- Do not fabricate citations.`,
        'data-survey': `You are a doctoral-level academic research assistant specializing in theoretical and conceptual analysis.

Task:
Conduct a structured theoretical literature investigation on the following topic:

[여기에 주제 입력]

Purpose:
This task is NOT for building a research model.
This task is for:
- Identifying core concepts
- Clarifying theoretical definitions
- Tracing conceptual evolution
- Collecting authoritative citations

Search Conditions:
- Publication years: [연도 범위 입력]
- Include foundational classical works and recent theoretical developments.
- Only include real, peer-reviewed journal articles or academic books.
- Do NOT fabricate citations.
- If bibliographic information is uncertain, clearly state uncertainty.
- Prioritize SSCI/SCIE/ESCI/Scopus-indexed journals when possible.

Required Output Structure:

I. Conceptual Definitions
- Provide multiple academic definitions.
- Compare differences in definition across scholars.
- Identify definitional debates if they exist.
- Clarify boundary conditions of the concept.

II. Theoretical Foundations
- Identify major theoretical frameworks underpinning the concept.
- Explain how each theory conceptualizes the construct.
- Indicate theoretical evolution over time.
- Distinguish normative, functional, and strategic perspectives where relevant.

III. Conceptual Structure
- Identify core dimensions or components.
- Indicate measurement traditions if applicable.
- Clarify conceptual overlaps with related constructs.

IV. Intellectual Genealogy
- Identify key scholars.
- Identify seminal works.
- Indicate how the concept has shifted historically.

V. Reference List
- Format strictly in APA 7th edition.
- Include DOI when available.
- Indicate journal indexing status (SSCI/SCIE/ESCI/Scopus if known).
- Separate domestic (Korean) and international literature if applicable.

Formatting Rules:
- Use formal academic tone.
- Avoid narrative summary.
- Structure analytically.
- Ensure terminological consistency.
- Do not generate fictional sources.

Explicitly distinguish between dictionary-style definitions and theory-based academic definitions.
Indicate which definitions are most frequently cited in SSCI literature.
Highlight conceptual ambiguities.`,
        'systematic-review': `You are a doctoral-level academic research assistant specializing in systematic literature review.

Task:
Conduct a structured literature review on the following topic:

[여기에 구체적 주제 입력]

Search Scope:
- Publication years: [연도 범위 입력]
- Include only real, peer-reviewed journal articles or academic books.
- Do NOT fabricate citations.
- If bibliographic details are uncertain, explicitly state uncertainty.
- Prioritize SSCI/SCIE/ESCI/Scopus-indexed journals when possible.
- Include both foundational classical theories and recent developments (post-2015).

Search Requirements:
- Identify major theoretical frameworks.
- Identify dominant research methodologies.
- Identify key dependent and independent variables used in prior studies.
- Highlight areas of consensus and debate.
- Identify research gaps.

Output Structure:

I. Theoretical Trends
- Major theoretical frameworks
- Evolution of key concepts
- Competing perspectives

II. Methodological Trends
- Dominant research designs (SEM, multilevel modeling, regression, meta-analysis, experimental, qualitative)
- Sample characteristics
- Measurement approaches

III. Empirical Findings Synthesis
- Consistent findings
- Contradictory findings
- Boundary conditions

IV. Research Gaps and Future Directions
- Theoretical gaps
- Methodological limitations
- Underexplored variables
- Suggestions for advanced modeling

V. Reference List
- APA 7th edition format
- Include DOI when available
- Indicate journal indexing status (if known)
- Separate domestic and international studies if applicable

Formatting Rules:
- Use formal academic tone.
- Avoid narrative storytelling.
- Structure analytically.
- Maintain conceptual precision.

Explicitly identify under-theorized areas.
Distinguish between statistical significance and theoretical contribution.
Indicate where longitudinal or multilevel modeling is needed.`,
        'academic-paper': `You are a doctoral-level academic research assistant specializing in education, organizational theory, and management research.

Task:
Produce three structured outputs on the following topic:

[여기에 구체적 주제 입력]
(e.g., Educational Industry Consulting and Organizational Outcomes)

The output must include:

------------------------------------------------------------
1. Conceptual and Theoretical Synthesis Sample
------------------------------------------------------------

Requirements:
- Define all key constructs clearly and academically.
- Compare competing definitions if they exist.
- Explain conceptual evolution over time.
- Identify theoretical linkages among constructs.
- Explicitly state theoretical foundations (e.g., systems theory, social exchange theory, human capital theory, organizational commitment theory).
- Maintain conceptual precision and terminological consistency.
- Avoid descriptive narration; structure analytically.

------------------------------------------------------------
2. Research Model Design Sample
------------------------------------------------------------

Requirements:
- Propose a logically grounded research model.
- Clearly identify:
  • Independent variables
  • Mediators (if applicable)
  • Dependent variables
  • Control variables (if relevant)
- Provide theoretical justification for each hypothesized path.
- Present 3–5 example hypotheses.
- Suggest appropriate methodology (e.g., SEM, multilevel modeling, mediation analysis).
- If possible, describe the conceptual framework in text-based diagram form.
- Indicate potential measurement scales if known.

------------------------------------------------------------
3. Empirical Evidence Review Sample (with APA references)
------------------------------------------------------------

Search Conditions:
- Publication years: [연도 범위 입력]
- Include only real, peer-reviewed journal articles or academic books.
- No fabricated citations.
- If bibliographic details are uncertain, explicitly state uncertainty.
- Prioritize SSCI/SCIE/ESCI/Scopus-indexed journals when possible.
- Include both classical foundational studies and recent developments (post-2015).

Output Requirements:
- Separate domestic (Korean) and international studies if applicable.
- For each cited study, briefly summarize:
  • Research purpose
  • Methodology
  • Key findings
- Format all references strictly in APA 7th edition.
- Include DOI when available.
- Indicate journal indexing status (if known).

------------------------------------------------------------
Formatting Rules:
------------------------------------------------------------
- Use formal academic tone.
- Ensure conceptual rigor.
- Maintain theoretical coherence.
- Do not generate fictional sources.
- Structure output using Roman numerals (I, II, III).

Prioritize conceptual and theoretical analysis over descriptive summaries.
Explicitly distinguish between normative, functional, and strategic perspectives.
Clarify differences between business consulting and educational consulting where relevant.`,
        citation: `You are an academic citation assistant.

Task:
Search for real, verifiable, peer-reviewed journal articles on:

[여기에 주제 입력]

Search Conditions:
- Publication years: [연도 범위 입력]
- Only include existing journal articles.
- Do NOT fabricate citations.
- If uncertain, clearly state uncertainty.

Output Requirements:
1. Format strictly in APA 7th edition.
2. Include DOI when available.
3. Indicate journal indexing status (SSCI/SCIE/ESCI/Scopus if known).
4. Separate domestic and international studies.
5. Provide 2–3 sentence structured summary for each:
   - Research purpose
   - Methodology
   - Key findings
6. Focus on theoretical and empirical contributions.

Formatting Rules:
- Do not include commentary.
- Only provide structured citation results.`
    };

    const _AI_SEARCH_VERIFICATION = `Before presenting results, verify that each article exists in recognized academic databases (Google Scholar, Crossref, Web of Science, Scopus, or official journal websites).
If verification is not possible, do not include the citation.`;

    function applyAiSearchPreset() {
        const sel = $('dr-ai-preset');
        const ta = $('dr-ai-preset-text');
        if (!sel || !ta) return;
        const key = sel.value || 'basic';
        ta.value = _AI_SEARCH_PRESETS[key] || _AI_SEARCH_PRESETS.basic;
    }

    function openCiteAiSearch() {
        hide();
        if (typeof App !== 'undefined' && App.showCite) App.showCite();
        if (typeof CM !== 'undefined' && CM.tab) setTimeout(() => CM.tab('ai-search'), 50);
    }

    return { show, hide, run, stopRun, runPro, switchTab, toggleMaximize, toggleThinking, toggleNewFile, insertToNewFile, insert, copyResult, copyThinking, clearOutput, openResultInNewWindow, openThinkingInNewWindow, openResultForTranslate, openThinkingForTranslate, thinkingTranslateGoogle, thinkingTranslateResultNewWindow, thinkingTranslateBothNewWindow, loadHistory, filterHistory, loadHistoryItem, renameHistory, deleteHistory, openHistorySaveModal, closeHistorySaveModal, saveHistoryAsZip, saveHistoryBatch, saveHistoryItemToFile, closeThinkingIncludeModal, confirmThinkingInclude, savePrePrompt, loadPrePrompt, runCiteAiSearch, openCiteAiSearch, applyAiSearchPreset, openPresetTextWindow, applyCiteAiSearchPreset, openCitePresetTextWindow, runCiteAiSearchFromModal, insertFromCiteModal, insertToNewFileFromCiteModal, copyResultFromCiteModal, openResultInNewWindowFromCiteModal, openResultForTranslateFromCiteModal, runDataResearch, applyDataResearchPreset, openDataPresetTextWindow };
})();
window.DeepResearch = DeepResearch;

/* Translator -> js/ai/translator.js */

/* CharMap -> js/ui/char-map.js */

/* ═══════════════════════════════════════════════════════
   SIDEBAR RESIZER — 사이드바 너비 드래그 조절
   ═══════════════════════════════════════════════════════ */
(function () {
    const MIN_W = 160;
    const MAX_W = 520;
    const DEFAULT_W = 240;
    const STORAGE_KEY = 'md_sidebar_width';

    let _dragging = false;
    let _startX = 0;
    let _startW = 0;

    function getEl() { return document.getElementById('sidebar-resizer'); }

    function getSidebarW() {
        const style = getComputedStyle(document.documentElement);
        const val = style.getPropertyValue('--sw').trim();
        return parseInt(val) || DEFAULT_W;
    }

    function setWidth(w) {
        w = Math.max(MIN_W, Math.min(MAX_W, w));
        document.documentElement.style.setProperty('--sw', w + 'px');
        positionResizer(w);
        try { localStorage.setItem(STORAGE_KEY, w); } catch(e) {}
    }

    function positionResizer(w) {
        const el = getEl();
        if (!el) return;
        const half = el.offsetWidth / 2;
        el.style.left = (w - half) + 'px';
        /* 앱 UI 영역(사이드바·메인 행) 안에서만 높이/위치 적용 — 모바일에서 화면 전체 터치 방지 */
        const main = document.getElementById('main');
        if (main) {
            const rect = main.getBoundingClientRect();
            el.style.top = rect.top + 'px';
            el.style.height = rect.height + 'px';
        }
    }

    function onMouseDown(e) {
        if (e.button !== 0) return;
        _dragging = true;
        _startX = e.clientX;
        _startW = getSidebarW();
        getEl().classList.add('dragging');
        document.body.classList.add('resizing');
        e.preventDefault();
    }

    function onTouchStart(e) {
        if (e.touches.length !== 1) return;
        _dragging = true;
        _startX = e.touches[0].clientX;
        _startW = getSidebarW();
        getEl().classList.add('dragging');
        document.body.classList.add('resizing');
    }

    function onTouchMove(e) {
        if (!_dragging) return;
        if (e.touches.length !== 1) return;
        e.preventDefault();
        const dx = e.touches[0].clientX - _startX;
        setWidth(_startW + dx);
    }

    function onTouchEnd() {
        if (!_dragging) return;
        _dragging = false;
        getEl().classList.remove('dragging');
        document.body.classList.remove('resizing');
    }

    function onMouseMove(e) {
        if (!_dragging) return;
        const dx = e.clientX - _startX;
        setWidth(_startW + dx);
    }

    function onMouseUp() {
        if (!_dragging) return;
        _dragging = false;
        getEl().classList.remove('dragging');
        document.body.classList.remove('resizing');
    }

    function init() {
        try {
            const saved = parseInt(localStorage.getItem(STORAGE_KEY));
            if (saved && saved >= MIN_W && saved <= MAX_W) {
                document.documentElement.style.setProperty('--sw', saved + 'px');
            }
        } catch(e) {}

        const el = getEl();
        if (!el) return;

        positionResizer(getSidebarW());
        el.addEventListener('mousedown', onMouseDown);
        el.addEventListener('touchstart', onTouchStart, { passive: true });
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
        document.addEventListener('touchmove', onTouchMove, { passive: false });
        document.addEventListener('touchend', onTouchEnd);
        document.addEventListener('touchcancel', onTouchEnd);

        el.addEventListener('dblclick', () => setWidth(DEFAULT_W));

        const appEl = document.getElementById('app');
        if (appEl) {
            new MutationObserver(() => positionResizer(getSidebarW()))
                .observe(appEl, { attributes: true, attributeFilter: ['class'] });
        }
        window.addEventListener('resize', () => positionResizer(getSidebarW()));
        window.addEventListener('load', () => positionResizer(getSidebarW()));
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

/* ScrollSync (문서 내) → js/editor/scroll-sync-doc.js */


/* ═══════════════════════════════════════════════════════════
   PVShare — md-viewer 공유 관리 시스템
   
   구조:
     [PV 패널 🔗 공유 버튼] → openModal() → md-viewer 관리 창
     [GH 파일행 📤 버튼]    → quickPush() → md-viewer에 바로 push

   md-viewer 관리 창:
     ┌────────────────────────────────────────────┐
     │ ⚙설정  🔄새로고침  ⬇Pull  ⬆Push  📋Clone  │
     │ ─────────────────────────────────────────  │
     │ 📁 폴더                                    │
     │   📄 파일.md    [🔗 링크복사] [🗑]         │
     │   📄 파일2.md   [🔗 링크복사] [🗑]         │
     │ [＋ 새파일] [📁 새폴더]                    │
     └────────────────────────────────────────────┘
═══════════════════════════════════════════════════════════ */
const PVShare = (() => {
    const CFG_KEY     = 'mdpro_viewer_cfg';
    const BTN_ID      = 'pv-share-btn';
    const VIEWER_URL  = 'https://shoutjoy.github.io/md-viewer/view.html';
    const LF_IDB_NAME = 'pvshare_local_db';
    const LF_FOLDER_KEY = 'pvshare_local_folder'; // localStorage: 폴더명 기억

    /* ── 설정 ── */
    function _loadCfg() {
        try { return JSON.parse(localStorage.getItem(CFG_KEY) || 'null'); }
        catch(e) { return null; }
    }
    function _saveCfg(c) {
        try { localStorage.setItem(CFG_KEY, JSON.stringify(c)); } catch(e) {}
    }

    /* ══════════════════════════════════════════════════
       PVShare 전용 로컬 폴더 관리 (FM과 완전 독립)
    ══════════════════════════════════════════════════ */
    let _pvDirHandle  = null;   // FileSystemDirectoryHandle
    let _pvFolderName = '';     // 폴더 표시명
    let _pvFiles      = [];     // { name, path, folder, content, size }

    /* ── 로컬 폴더명 localStorage 저장/복원 ── */
    function _pvSaveFolderName(name) {
        try { localStorage.setItem(LF_FOLDER_KEY, name || ''); } catch(e) {}
    }
    function _pvLoadFolderName() {
        try { return localStorage.getItem(LF_FOLDER_KEY) || ''; } catch(e) { return ''; }
    }

    /* ── 디렉터리 재귀 스캔 ── */
    async function _pvScanDir(handle, basePath, depth, out) {
        if (depth > 6) return;
        for await (const [entryName, entry] of handle.entries()) {
            if (entryName.startsWith('.')) continue;
            const relPath = basePath ? basePath + '/' + entryName : entryName;
            if (entry.kind === 'directory') {
                /* 서브폴더 스캔 → 결과 없으면 빈 폴더 항목 추가 */
                const lenBefore = out.length;
                await _pvScanDir(entry, relPath, depth + 1, out);
                if (out.length === lenBefore) {
                    /* .gitkeep 전용이거나 완전히 빈 폴더 */
                    out.push({ name: entryName, path: relPath,
                                folder: basePath || '', content: null,
                                size: 0, isDir: true });
                }
            } else {
                /* 텍스트 기반 파일은 content 바로 로드 */
                let content = null;
                let fileSize = 0;
                if (entryName.match(/\.(md|txt|markdown|html|json|yaml|yml|csv)$/i)) {
                    try {
                        const file = await entry.getFile();
                        fileSize = file.size;
                        content = await file.text();
                    } catch(e) { content = ''; }
                } else {
                    try {
                        const file = await entry.getFile();
                        fileSize = file.size;
                    } catch(e) {}
                }
                out.push({
                    name: entryName,
                    path: relPath,
                    folder: basePath || '',
                    content,
                    size: fileSize,
                    isDir: false,
                });
            }
        }
    }

    /* ── 폴더 선택 (PVShare 전용) ── */
    async function _pvSelectFolder() {
        if (!window.showDirectoryPicker) {
            App._toast('⚠ 이 브라우저는 로컬 폴더 접근을 지원하지 않습니다');
            return false;
        }
        try {
            const h = await window.showDirectoryPicker({ mode: 'readwrite' });
            _pvDirHandle  = h;
            _pvFolderName = h.name;
            _pvSaveFolderName(h.name);
            App._toast('⟳ 공개노트 폴더 스캔 중…');
            await _pvSync();
            return true;
        } catch(e) {
            if (e.name !== 'AbortError') App._toast('⚠ 폴더 선택 실패: ' + e.message);
            return false;
        }
    }

    /* ── 핸들에서 파일 목록 동기화 ── */
    async function _pvSync() {
        if (!_pvDirHandle) return;
        const fresh = [];
        await _pvScanDir(_pvDirHandle, '', 0, fresh);
        _pvFiles = fresh;
        App._toast('✅ 공개노트 폴더 동기화 완료: ' + _pvFiles.length + '개');
    }

    /* ── 권한 재요청 (재시작 후 핸들 복원 시) ── */
    async function _pvRequestPermission() {
        if (!_pvDirHandle) return false;
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            return perm === 'granted';
        } catch(e) { return false; }
    }

    /* ── GitHub API (viewer 저장소) ── */
    async function _api(path, opts = {}) {
        const token = GH.cfg?.token;
        if (!token) throw new Error('GitHub 토큰이 없습니다 (GH 설정 확인)');
        const cfg  = _loadCfg();
        const repo = cfg?.repo || 'shoutjoy/md-viewer';
        const base = `https://api.github.com/repos/${repo}`;
        const url  = path.startsWith('http') ? path : base + path;
        const res  = await fetch(url, {
            ...opts,
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'X-GitHub-Api-Version': '2022-11-28',
                ...(opts.headers || {}),
            },
        });
        if (res.status === 204) return {};
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(`GitHub ${res.status}: ${err.message || res.statusText}`);
        }
        return res.json();
    }

    /* ── 파일 목록 조회 ── */
    async function _listPath(path = '') {
        return _api(`/contents/${path ? encodeURIComponent(path) : ''}`);
    }

    /* ── 파일 내용 조회 ── */
    async function _getFile(path) {
        return _api(`/contents/${encodeURIComponent(path)}`);
    }

    /* ── 파일 쓰기 (PUT) ── */
    async function _putFile(path, content, message, sha = null) {
        const body = {
            message,
            content: btoa(unescape(encodeURIComponent(content))),
            branch: _loadCfg()?.branch || 'main',
        };
        if (sha) body.sha = sha;
        return _api(`/contents/${encodeURIComponent(path)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
    }

    /* ── 파일 삭제 ── */
    async function _deleteFile(path, sha, message) {
        return _api(`/contents/${encodeURIComponent(path)}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                sha,
                branch: _loadCfg()?.branch || 'main',
            }),
        });
    }

    /* ── 브랜치 HEAD SHA ── */
    async function _getHeadSHA(branch = 'main') {
        const ref = await _api(`/git/ref/heads/${branch}`);
        return ref.object.sha;
    }

    /* ── 폴더 내 파일 전체 삭제 (Trees API) ── */
    async function _deleteFolderContents(folderPath, allItems) {
        const cfg    = _loadCfg();
        const branch = cfg?.branch || 'main';
        const repo   = cfg?.repo || 'shoutjoy/md-viewer';
        const token  = GH.cfg?.token;

        const headSHA  = await _getHeadSHA(branch);
        const commitRes = await fetch(`https://api.github.com/repos/${repo}/git/commits/${headSHA}`, {
            headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json' }
        }).then(r => r.json());
        const baseTreeSHA = commitRes.tree.sha;

        const delItems = allItems
            .filter(f => f.type === 'blob' && f.path.startsWith(folderPath + '/'))
            .map(f => ({ path: f.path, mode: '100644', type: 'blob', sha: null }));

        if (!delItems.length) return;

        const treeRes = await fetch(`https://api.github.com/repos/${repo}/git/trees`, {
            method: 'POST',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ base_tree: baseTreeSHA, tree: delItems }),
        }).then(r => r.json());

        const newCommit = await fetch(`https://api.github.com/repos/${repo}/git/commits`, {
            method: 'POST',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: `Delete folder: ${folderPath}`,
                tree: treeRes.sha,
                parents: [headSHA],
            }),
        }).then(r => r.json());

        await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/${branch}`, {
            method: 'PATCH',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ sha: newCommit.sha }),
        });
    }

    /* ── 링크 생성 ── */
    function _makeLink(filePath) {
        const cfg  = _loadCfg();
        const repo = cfg?.repo || 'shoutjoy/md-viewer';
        const branch = cfg?.branch || 'main';
        /* docs/ 안의 파일이면 ?doc= 방식 (정적 fetch) */
        if (filePath.startsWith('docs/')) {
            const docName = filePath.replace(/^docs\//, '').replace(/\.md$/i, '');
            return `${VIEWER_URL}?doc=${encodeURIComponent(docName)}`;
        }
        /* 그 외는 repo+path 방식 */
        return `${VIEWER_URL}?repo=${repo}&branch=${branch}&path=${encodeURIComponent(filePath)}`;
    }

    /* ── 버튼 표시/숨김 ── */
    function refresh() {
        const btn = document.getElementById(BTN_ID);
        if (!btn) return;
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        btn.style.display = tab ? '' : 'none';
    }

    /* ══════════════════════════════════════════════════
       메인 모달 열기
    ══════════════════════════════════════════════════ */
    function openModal() {
        const existing = document.getElementById('pvshare-overlay');
        if (existing) { existing.remove(); return; }

        const vcfg = _loadCfg();

        const ov = document.createElement('div');
        ov.id = 'pvshare-overlay';
        ov.style.cssText = [
            'position:fixed;inset:0;z-index:9100',
            'background:rgba(0,0,0,.65)',
            'display:flex;align-items:center;justify-content:center;padding:16px',
        ].join(';');

        ov.innerHTML = `
        <div id="pvs-box" style="
            background:var(--bg2);border:1px solid var(--bd);border-radius:14px;
            width:540px;max-width:95vw;max-height:88vh;
            display:flex;flex-direction:column;
            box-shadow:0 16px 60px rgba(0,0,0,.7);overflow:hidden">

          <!-- 헤더 -->
          <div style="display:flex;align-items:center;gap:8px;
              padding:12px 16px;border-bottom:1px solid var(--bd);
              background:var(--bg3);flex-shrink:0">
            <span style="font-size:13px;font-weight:700;color:#58c8f8">📤 공개노트 설정</span>
            <a id="pvs-repo-name" href="${vcfg ? `https://github.com/${vcfg.repo}` : '#'}"
                target="_blank" rel="noopener noreferrer"
                title="GitHub 저장소 열기"
                style="font-size:11px;color:#a090ff;flex:1;
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
                    text-decoration:none;cursor:pointer;
                    padding:2px 6px;border-radius:4px;
                    background:rgba(160,144,255,.1);
                    border:1px solid rgba(160,144,255,.2);
                    transition:background .15s"
                onmouseover="this.style.background='rgba(160,144,255,.22)'"
                onmouseout="this.style.background='rgba(160,144,255,.1)'">
              ${vcfg ? vcfg.repo : '저장소 미설정'} ↗</a>
            <button onclick="PVShare._showSettings()" title="저장소 설정"
                style="background:rgba(255,255,255,.08);border:1px solid var(--bd);
                    border-radius:5px;color:var(--tx2);font-size:11px;
                    padding:3px 9px;cursor:pointer">⚙ 설정</button>
            <button id="pvs-close" style="background:none;border:none;cursor:pointer;
                color:var(--tx3);font-size:18px;padding:0 4px;line-height:1">✕</button>
          </div>

          <!-- 툴바 -->
          <div style="display:flex;align-items:center;gap:6px;
              padding:8px 14px;border-bottom:1px solid var(--bd);
              background:var(--bg3);flex-shrink:0;flex-wrap:wrap">
            <button onclick="PVShare._refresh()" title="새로고침"
                style="background:rgba(255,255,255,.07);border:1px solid var(--bd);
                    border-radius:5px;color:var(--tx2);font-size:11px;
                    padding:4px 10px;cursor:pointer">↻ 새로고침</button>
            <button onclick="PVShare._pull()" title="원격 변경사항 반영"
                style="background:rgba(88,200,248,.1);border:1px solid rgba(88,200,248,.3);
                    border-radius:5px;color:#58c8f8;font-size:11px;
                    padding:4px 10px;cursor:pointer">⬇ Pull</button>
            <button onclick="PVShare._pushCurrent()" title="현재 에디터 문서 Push"
                style="background:rgba(106,247,176,.1);border:1px solid rgba(106,247,176,.3);
                    border-radius:5px;color:#6af7b0;font-size:11px;
                    padding:4px 10px;cursor:pointer">⬆ Push</button>
            <button onclick="PVShare._cloneModal()" title="저장소 Clone"
                style="background:rgba(106,247,176,.1);border:1px solid rgba(106,247,176,.28);
                    border-radius:5px;color:#6af7b0;font-size:11px;
                    padding:4px 10px;cursor:pointer">⎘ Clone</button>
            <span id="pvs-status" style="font-size:10px;color:var(--tx3);margin-left:6px"></span>
          </div>

          <!-- 로컬 / GitHub 탭 -->
          <div style="display:flex;border-bottom:1px solid var(--bd);background:var(--bg3);flex-shrink:0">
            <button id="pvs-tab-local" onclick="PVShare._switchTab('local')"
                style="flex:1;padding:9px;font-size:12px;font-weight:600;border:none;cursor:pointer;
                    border-bottom:2px solid #58c8f8;
                    background:rgba(88,200,248,.08);color:#58c8f8;
                    transition:all .15s">
                💻 로컬</button>
            <button id="pvs-tab-github" onclick="PVShare._switchTab('github')"
                style="flex:1;padding:9px;font-size:12px;font-weight:600;border:none;cursor:pointer;
                    border-bottom:2px solid transparent;
                    background:transparent;color:var(--tx3);
                    transition:all .15s">
                🐙 GitHub</button>
          </div>

          <!-- 검색 -->
          <div style="padding:8px 14px;border-bottom:1px solid var(--bd);flex-shrink:0">
            <input id="pvs-search" type="text" placeholder="파일 검색…"
                oninput="PVShare._search(this.value)"
                style="width:100%;background:var(--bg3);border:1px solid var(--bd);
                    border-radius:6px;color:var(--tx);font-size:12px;
                    padding:6px 10px;outline:none;box-sizing:border-box">
          </div>

          <!-- 파일 목록 -->
          <div id="pvs-list" style="flex:1;overflow-y:auto;padding:6px 0;min-height:120px">
            <div style="text-align:center;padding:30px;color:var(--tx3);font-size:12px">
              ⟳ 파일 목록 불러오는 중…
            </div>
          </div>

          <!-- 하단 액션: [새파일] [새폴더] [자동새로고침] [25s] {설정} -->
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;
              border-top:1px solid var(--bd);background:var(--bg3);flex-shrink:0;flex-wrap:wrap">
            <button id="pvs-btn-newfile" onclick="PVShare._dispatchNewFile()" title="새 파일 만들기"
                style="flex:1;min-width:90px;padding:7px;border-radius:6px;
                    background:rgba(255,255,255,.06);border:1px solid var(--bd);
                    color:var(--tx2);font-size:12px;cursor:pointer">
                새 파일</button>
            <button id="pvs-btn-newfolder" onclick="PVShare._dispatchNewFolder()" title="새 폴더 만들기"
                style="flex:1;min-width:90px;padding:7px;border-radius:6px;
                    background:rgba(255,255,255,.06);border:1px solid var(--bd);
                    color:var(--tx2);font-size:12px;cursor:pointer">
                새 폴더</button>
            <button id="pvs-ar-btn" onclick="PVShare._toggleAutoRefresh()"
                title="GitHub 폴더 목록 자동 새로고침 ON/OFF"
                style="border-radius:5px;font-size:11px;padding:4px 10px;cursor:pointer;
                    font-weight:600;transition:all .2s;
                    color:#6af7b0;border:1px solid rgba(106,247,176,.35);
                    background:rgba(106,247,176,.1)">🔄 자동새로고침 ON</button>
            <span id="pvs-ar-countdown"
                style="font-size:11px;color:var(--tx3);min-width:28px;text-align:center;display:none"></span>
            <button onclick="PVShare._showArIntervalSetting()" title="자동 새로고침 간격(초) 설정"
                style="padding:6px 12px;border-radius:5px;border:1px solid var(--bd);
                    background:rgba(255,255,255,.06);color:var(--tx2);font-size:11px;cursor:pointer">
                ⚙ 설정</button>
          </div>
        </div>`;

        document.body.appendChild(ov);

        /* 닫기 */
        document.getElementById('pvs-close').onclick = () => {
            _stopAutoRefresh();
            ov.remove();
        };
        /* 모달 열릴 때 자동새로고침 버튼 상태 반영 + 시작 */
        setTimeout(() => {
            _arUpdateBtn();
            if (_arEnabled) _startAutoRefresh();
        }, 50);
        ov.onclick = (e) => { if (e.target === ov) ov.remove(); };

        /* 기본 탭: 로컬 탭 활성 */
        setTimeout(() => { _switchTab('local'); }, 0);
    }

    /* ── 파일 목록 렌더 ── */
    let _allFiles = [];
    let _searchQ  = '';
    let _currentGitHubPath = '';  /* GitHub 탭에서 현재 보고 있는 경로 (자동새로고침용) */

    async function _loadList(path = '') {
        const listEl = document.getElementById('pvs-list');
        if (!listEl) return;
        _currentGitHubPath = path;  /* 자동새로고침 시 같은 경로로 재요청 */
        _setStatus('불러오는 중…');

        const vcfg = _loadCfg();
        if (!vcfg?.repo) {
            listEl.innerHTML = `
            <div style="text-align:center;padding:30px;color:#f7c060;font-size:12px">
                ⚠ 저장소가 설정되지 않았습니다.<br>
                <button onclick="PVShare._showSettings()"
                    style="margin-top:10px;padding:6px 14px;border-radius:6px;
                        background:rgba(247,192,96,.15);border:1px solid rgba(247,192,96,.3);
                        color:#f7c060;font-size:12px;cursor:pointer">⚙ 설정하기</button>
            </div>`;
            _setStatus('');
            return;
        }

        try {
            const items = await _listPath(path);
            _allFiles = Array.isArray(items) ? items : [];
            _renderList(_allFiles);
            _setStatus('');
        } catch(e) {
            listEl.innerHTML = `
            <div style="text-align:center;padding:20px;color:#f76a6a;font-size:12px">
                ❌ ${e.message}<br>
                <button onclick="PVShare._loadList()"
                    style="margin-top:8px;padding:5px 12px;border-radius:5px;
                        background:rgba(247,106,106,.1);border:1px solid rgba(247,106,106,.3);
                        color:#f76a6a;font-size:11px;cursor:pointer">다시 시도</button>
            </div>`;
            _setStatus('오류');
        }
    }

    function _renderList(items) {
        const listEl = document.getElementById('pvs-list');
        if (!listEl) return;

        const q = _searchQ.toLowerCase();
        const filtered = q ? items.filter(f => f.name.toLowerCase().includes(q)) : items;

        if (!filtered.length) {
            listEl.innerHTML = `<div style="text-align:center;padding:24px;
                color:var(--tx3);font-size:12px">파일이 없습니다</div>`;
            return;
        }

        /* 폴더 먼저, 파일 나중 */
        const sorted = [...filtered].sort((a, b) => {
            if (a.type === b.type) return a.name.localeCompare(b.name);
            return a.type === 'dir' ? -1 : 1;
        });

        listEl.innerHTML = sorted.map(f => {
            const isDir  = f.type === 'dir';
            const icon   = isDir ? '📁' : (f.name.endsWith('.md') ? '📄' : '📎');
            const link   = isDir ? '' : _makeLink(f.path);
            const linkBtn = isDir ? '' : `
                <button onclick="event.stopPropagation();PVShare._copyLink('${_escQ(link)}',this)"
                    title="뷰어 링크 복사"
                    style="background:rgba(88,200,248,.12);border:1px solid rgba(88,200,248,.3);
                        border-radius:4px;color:#58c8f8;font-size:10px;
                        padding:2px 7px;cursor:pointer;flex-shrink:0">🔗</button>`;

            return `<div class="pvs-item" data-path="${_escQ(f.path)}" data-type="${f.type}"
                data-sha="${f.sha || ''}"
                style="display:flex;align-items:center;gap:6px;
                    padding:5px 14px;cursor:pointer;border-radius:4px;
                    transition:background .1s"
                onmouseover="this.style.background='rgba(255,255,255,.05)'"
                onmouseout="this.style.background=''"
                onclick="PVShare._itemClick(this)">
              <span style="flex-shrink:0;font-size:13px">${icon}</span>
              <span style="flex:1;font-size:12px;color:var(--tx);
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(f.name)}</span>
              ${linkBtn}
              <button onclick="event.stopPropagation();PVShare._moveFile(this)"
                  data-path="${_escQ(f.path)}" data-type="${f.type}"
                  title="이동"
                  style="background:rgba(255,255,255,.06);border:1px solid var(--bd);
                      border-radius:4px;color:var(--tx3);font-size:10px;
                      padding:2px 7px;cursor:pointer;flex-shrink:0">↗</button>
              <button onclick="event.stopPropagation();PVShare._deleteItem(this)"
                  data-path="${_escQ(f.path)}" data-type="${f.type}"
                  data-sha="${_escQ(f.sha || '')}" data-name="${_escQ(f.name)}"
                  title="삭제"
                  style="background:rgba(247,106,106,.1);border:1px solid rgba(247,106,106,.25);
                      border-radius:4px;color:#f76a6a;font-size:10px;
                      padding:2px 7px;cursor:pointer;flex-shrink:0">🗑</button>
            </div>`;
        }).join('');
    }

    function _escQ(s) { return String(s).replace(/'/g,"\\'").replace(/"/g,'&quot;'); }
    function _esc(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    /* ── 아이템 클릭: 폴더면 하위 목록, 파일이면 열기 ── */
    function _itemClick(row) {
        const path = row.dataset.path;
        const type = row.dataset.type;
        if (type === 'dir') {
            _loadList(path);
        }
    }

    /* ── 검색 ── */
    function _search(q) {
        _searchQ = q;
        _renderList(_allFiles);
    }

    /* ── 링크 복사 ── */
    function _copyLink(url, btn) {
        navigator.clipboard.writeText(url).then(() => {
            const orig = btn.textContent;
            btn.textContent = '✅';
            btn.style.color = '#6af7b0';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
            App._toast('🔗 링크 복사됨: ' + url);
        }).catch(() => {
            prompt('링크를 복사하세요:', url);
        });
    }

    /* ── 상태 텍스트 ── */
    function _setStatus(msg) {
        const el = document.getElementById('pvs-status');
        if (el) el.textContent = msg;
    }

    /* ── 새로고침 ── */
    function _refresh() { _loadList(); }

    /* ── Pull: 원격 최신 파일 목록 갱신 ── */
    function _pull() {
        _setStatus('Pull 중…');
        _loadList().then(() => App._toast('⬇ Pull 완료'));
    }

    /* ── Push: 현재 에디터 문서를 docs/ 에 push ── */
    async function _pushCurrent() {
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        if (!tab) { App._toast('⚠ 열린 문서가 없습니다'); return; }

        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const defaultName = (tab.title || '문서')
            .replace(/[^a-zA-Z0-9가-힣._-]/g,'_')
            .replace(/\.md$/i,'') + '.md';

        const name = prompt('저장할 파일명 (docs/ 안에 저장됩니다):', defaultName);
        if (!name) return;

        const filePath = 'docs/' + name;
        const content  = document.getElementById('editor')?.value || '';
        _setStatus('Push 중…');

        try {
            let sha = null;
            try { const ex = await _getFile(filePath); sha = ex.sha; } catch(e) {}
            await _putFile(filePath, content, `Publish: ${name}`, sha);
            _setStatus('');
            _loadList();
            const link = _makeLink(filePath);
            App._toast('✅ Push 완료');
            _showLinkResult(link, name);
        } catch(e) {
            _setStatus('오류');
            alert('Push 실패: ' + e.message);
        }
    }

    /* ── 로컬 / GitHub 탭 전환 ── */
    let _activeTab = 'local';   /* 현재 활성 탭: 'local' | 'github' */

    /* ── 자동 새로고침 ─────────────────────────────────────── */
    const AR_KEY      = 'pvs_auto_refresh';   // localStorage 키
    const AR_INTERVAL_KEY = 'pvs_ar_interval'; // 간격(초) 저장 키
    function _getArInterval() { return Math.max(10, parseInt(localStorage.getItem(AR_INTERVAL_KEY) || '30', 10) || 30); }
    let _arEnabled    = localStorage.getItem(AR_KEY) !== 'off'; // 기본 ON
    let _arTimer      = null;   // setInterval ID
    let _arCountdown  = 0;      // 남은 초
    let _arTick       = null;   // 카운트다운 ticker

    function _arSaveState() {
        localStorage.setItem(AR_KEY, _arEnabled ? 'on' : 'off');
    }

    function _arUpdateBtn() {
        const btn = document.getElementById('pvs-ar-btn');
        if (!btn) return;
        if (_arEnabled) {
            btn.textContent = '🔄 자동새로고침 ON';
            btn.style.color      = '#6af7b0';
            btn.style.borderColor = 'rgba(106,247,176,.35)';
            btn.style.background  = 'rgba(106,247,176,.1)';
        } else {
            btn.textContent = '🔄 자동새로고침 OFF';
            btn.style.color      = 'var(--tx3)';
            btn.style.borderColor = 'var(--bd)';
            btn.style.background  = 'rgba(255,255,255,.04)';
        }
    }

    function _arUpdateCountdown() {
        const el = document.getElementById('pvs-ar-countdown');
        if (!el) return;
        if (_arEnabled && _arCountdown > 0) {
            el.textContent = _arCountdown + 's';
            el.style.display = 'inline';
        } else {
            el.style.display = 'none';
        }
    }

    function _startAutoRefresh() {
        _stopAutoRefresh();
        if (!_arEnabled) return;
        const intervalSec = _getArInterval();
        _arCountdown = intervalSec;
        _arUpdateCountdown();

        // 카운트다운 ticker (1초마다)
        _arTick = setInterval(() => {
            _arCountdown--;
            _arUpdateCountdown();
            if (_arCountdown <= 0) {
                // GitHub 탭 활성 상태일 때만 GitHub 폴더 목록 새로고침 (현재 경로 유지)
                if (_activeTab === 'github') {
                    _loadList(_currentGitHubPath).catch(() => {});
                }
                _arCountdown = _getArInterval();
            }
        }, 1000);
    }

    function _stopAutoRefresh() {
        if (_arTimer)  { clearInterval(_arTimer);  _arTimer   = null; }
        if (_arTick)   { clearInterval(_arTick);   _arTick    = null; }
        _arCountdown = 0;
        _arUpdateCountdown();
    }

    function _toggleAutoRefresh() {
        _arEnabled = !_arEnabled;
        _arSaveState();
        _arUpdateBtn();
        if (_arEnabled) {
            _startAutoRefresh();
            App._toast('🔄 자동새로고침 ON (' + _getArInterval() + '초마다 GitHub 폴더)');
        } else {
            _stopAutoRefresh();
            App._toast('🔄 자동새로고침 OFF');
        }
    }

    /* 자동새로고침 간격(초) 설정 */
    function _showArIntervalSetting() {
        const cur = _getArInterval();
        const v = prompt('자동 새로고침 간격 (초)\nGitHub 탭에서 이 간격마다 폴더 목록을 갱신합니다.', String(cur));
        if (v == null) return;
        const num = parseInt(v, 10);
        if (!(num >= 10 && num <= 600)) {
            App._toast('⚠ 10~600 초 사이로 입력하세요');
            return;
        }
        localStorage.setItem(AR_INTERVAL_KEY, String(num));
        if (_arEnabled) _startAutoRefresh();
        App._toast('✅ 간격 ' + num + '초로 저장');
    }

    function _switchTab(tab) {
        _activeTab = tab;
        const localBtn  = document.getElementById('pvs-tab-local');
        const githubBtn = document.getElementById('pvs-tab-github');
        if (!localBtn || !githubBtn) return;

        if (tab === 'local') {
            localBtn.style.borderBottomColor  = '#58c8f8';
            localBtn.style.background         = 'rgba(88,200,248,.08)';
            localBtn.style.color              = '#58c8f8';
            githubBtn.style.borderBottomColor = 'transparent';
            githubBtn.style.background        = 'transparent';
            githubBtn.style.color             = 'var(--tx3)';
            _renderLocalFiles();
        } else {
            githubBtn.style.borderBottomColor = '#a090ff';
            githubBtn.style.background        = 'rgba(160,144,255,.08)';
            githubBtn.style.color             = '#a090ff';
            localBtn.style.borderBottomColor  = 'transparent';
            localBtn.style.background         = 'transparent';
            localBtn.style.color              = 'var(--tx3)';
            _loadList();
        }
        /* 하단 버튼 라벨을 탭에 맞게 갱신 */
        _updateBottomBtns(tab);
    }

    /* 하단 새파일/새폴더 버튼 라벨 갱신 */
    function _updateBottomBtns(tab) {
        const btnFile   = document.getElementById('pvs-btn-newfile');
        const btnFolder = document.getElementById('pvs-btn-newfolder');
        if (!btnFile || !btnFolder) return;
        if (tab === 'local') {
            btnFile.textContent   = '새 파일';
            btnFolder.textContent = '새 폴더';
            btnFile.title   = '로컬 공개노트 폴더에 새 파일 생성';
            btnFolder.title = '로컬 공개노트 폴더에 새 폴더 생성';
        } else {
            btnFile.textContent   = '새 파일';
            btnFolder.textContent = '새 폴더';
            btnFile.title   = 'md-viewer GitHub 저장소에 새 파일 생성';
            btnFolder.title = 'md-viewer GitHub 저장소에 새 폴더 생성';
        }
    }

    /* ── 로컬 탭 파일 목록 렌더 ── */
    /* ══════════════════════════════════════════════════
       공개노트 로컬 탭 — PVShare 전용 폴더 렌더
    ══════════════════════════════════════════════════ */
    function _renderLocalFiles() {
        const list = document.getElementById('pvs-list');
        if (!list) return;

        const curFolder = _pvFolderName || _pvLoadFolderName() || '';
        const files     = _pvFiles || [];

        /* ── 폴더 상태 헤더 (sticky) ── */
        const folderBar = `
            <div id="pvs-local-folderbar" style="display:flex;align-items:center;gap:8px;
                padding:8px 14px;background:var(--bg3);border-bottom:1px solid var(--bd);
                position:sticky;top:0;z-index:2;flex-shrink:0">
              <span style="font-size:12px">📂</span>
              <span id="pvs-local-foldername" style="flex:1;font-size:11px;font-weight:600;
                  color:${curFolder ? 'var(--tx)' : 'var(--tx3)'};
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  ${curFolder || '공개노트 폴더 미선택'}</span>
              <button onclick="PVShare._selectLocalFolder()"
                  style="padding:3px 11px;border-radius:5px;white-space:nowrap;flex-shrink:0;
                      border:1px solid rgba(88,200,248,.45);font-size:10.5px;cursor:pointer;
                      background:rgba(88,200,248,.1);color:#58c8f8">
                  ${curFolder ? '📂 변경' : '📂 폴더 선택'}</button>
              ${curFolder ? `<button onclick="PVShare._pvRefresh()"
                  title="폴더 새로고침"
                  style="padding:3px 8px;border-radius:5px;border:1px solid var(--bd);
                      background:rgba(255,255,255,.06);color:var(--tx3);font-size:11px;cursor:pointer">↻</button>` : ''}
              ${curFolder ? `<button onclick="PVShare._pvOpenLocalDir()"
                  title="연결된 로컬 폴더 탐색기에서 열기"
                  style="padding:3px 9px;border-radius:5px;border:1px solid rgba(247,201,106,.4);
                      background:rgba(247,201,106,.1);color:#f7c96a;font-size:10.5px;cursor:pointer;white-space:nowrap">📂 열기</button>` : ''}
            </div>`;

        /* 폴더 없거나 파일 없음 */
        if (!files.length) {
            list.innerHTML = folderBar + `
                <div style="text-align:center;padding:30px 16px;color:var(--tx3);font-size:12px;line-height:1.8">
                  ${curFolder
                    ? '<span style="font-size:22px">📭</span><br>파일이 없거나 스캔 중입니다.<br><button onclick="PVShare._pvRefresh()" style="margin-top:8px;padding:4px 14px;border-radius:5px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:11px;cursor:pointer">↻ 다시 스캔</button>'
                    : '<span style="font-size:22px">💻</span><br>공개노트(md-viewer)와 공유할<br>로컬 폴더를 선택하세요.'
                  }
                </div>`;
            return;
        }

        /* 폴더 → 파일 구분 정렬: .md 먼저, 나머지 나중 / isDir 빈폴더 별도 */
        const emptyDirs = files.filter(f => f.isDir);
        const realFiles = files.filter(f => !f.isDir);
        const mdFiles   = realFiles.filter(f => f.name.match(/\.md$/i));
        const others    = realFiles.filter(f => !f.name.match(/\.md$/i));
        const sorted    = [...mdFiles, ...others];

        /* 폴더 그룹핑 (folder 값 기준) */
        const grouped = {};
        sorted.forEach(f => {
            const grp = f.folder || '';
            if (!grouped[grp]) grouped[grp] = [];
            grouped[grp].push(f);
        });

        /* 빈 폴더: 아직 grouped 에 없는 경우 빈 배열로 등록 */
        emptyDirs.forEach(d => {
            /* d.folder = 부모 경로, d.path = 이 폴더 경로 */
            /* 빈 폴더를 부모 그룹 아래 배치 */
            const grp = d.folder || '';
            if (!grouped[grp]) grouped[grp] = [];
            grouped[grp].push(d);   /* isDir:true 항목 포함 */
        });

        let html = folderBar;

        Object.keys(grouped).sort().forEach(grpKey => {
            html += `<div class="pvs-local-group" data-path="${_escQL(grpKey)}">`;
            if (grpKey) {
                html += `<div class="pvs-local-group-hdr" style="display:flex;align-items:center;gap:6px;
                    padding:5px 14px 3px;font-size:10.5px;color:var(--tx3);
                    font-weight:600;background:rgba(255,255,255,.02);
                    border-bottom:1px solid rgba(255,255,255,.04);cursor:pointer;user-select:none">
                  <span class="ft-toggle">▾</span>
                  <span class="ft-folder-icon">📁</span>
                  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_escL(grpKey)}</span>
                  <span class="ft-folder-lock" title="접었을 때 잠금 — 새로고침 시에도 접힌 상태 유지" role="button">▼</span>
                  <button onclick="event.stopPropagation();PVShare._pvCreateFileInFolder('${_escQL(grpKey)}')"
                      title="이 폴더에 새 파일 만들기"
                      style="padding:1px 7px;border-radius:4px;font-size:11px;cursor:pointer;flex-shrink:0;
                          border:1px solid rgba(106,247,176,.3);background:rgba(106,247,176,.07);color:#6af7b0;line-height:1.4">📄＋</button>
                  <button onclick="event.stopPropagation();PVShare._pvCreateFolderIn('${_escQL(grpKey)}')"
                      title="이 폴더 안에 새 하위 폴더 만들기"
                      style="padding:1px 7px;border-radius:4px;font-size:11px;cursor:pointer;flex-shrink:0;
                          border:1px solid rgba(247,201,106,.3);background:rgba(247,201,106,.07);color:#f7c96a;line-height:1.4">📁＋</button>
                </div>`;
            }
            html += `<div class="pvs-local-group-body">`;
            grouped[grpKey].forEach(f => {
                /* ── 빈 폴더 항목 (isDir:true) ── */
                if (f.isDir) {
                    html += `<div class="pvs-local-item pvs-empty-dir"
                        data-path="${_escQL(f.path)}"
                        data-name="${_escQL(f.name)}"
                        data-folder="${_escQL(f.folder || '')}"
                        style="display:flex;align-items:center;gap:6px;
                            padding:5px 14px 5px 24px;
                            border-bottom:1px solid rgba(255,255,255,.025);
                            font-size:11.5px;color:var(--tx3)">
                      <span style="font-size:12px;flex-shrink:0">📁</span>
                      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-style:italic">${_escL(f.name)}</span>
                      <span style="font-size:10px;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:4px;flex-shrink:0">빈 폴더</span>
                    </div>`;
                    return;
                }
                const icon = f.name.match(/\.md$/i) ? '📝' : '📄';
                /* data-path / data-name 에 경로 저장 → 함수에서 closest로 읽음
                   JSON.stringify를 onclick 속성에 직접 삽입하면
                   큰따옴표 충돌로 HTML이 깨지므로 btn-only 방식 사용 */
                html += `
                <div class="pvs-local-item"
                    data-path="${_escQL(f.path)}"
                    data-name="${_escQL(f.name)}"
                    data-folder="${_escQL(f.folder || '')}"
                    style="display:flex;align-items:center;gap:6px;
                        padding:6px 14px;border-bottom:1px solid rgba(255,255,255,.035);
                        font-size:12px;color:var(--tx2);cursor:pointer;transition:background .1s"
                    onmouseover="this.style.background='rgba(255,255,255,.045)'"
                    onmouseout="this.style.background=''"
                    onclick="PVShare._pvOpenFile(this)"
                    ontouchstart="(function(row,ev){
                        if(ev.target.closest('button')){return;}
                        var already=row.classList.contains('touch-sel');
                        document.querySelectorAll('.pvs-local-item.touch-sel').forEach(function(el){if(el!==row)el.classList.remove('touch-sel');});
                        if(already){PVShare._pvOpenFile(row);row.classList.remove('touch-sel');}
                        else{row.classList.add('touch-sel');ev.preventDefault();}
                    })(this,event)">
                  <span style="font-size:12px;flex-shrink:0">${icon}</span>
                  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${_escL(f.name)}</span>
                  <!-- 비공개 커밋 (mdliveData GH) -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvPushPrivate(this)"
                      title="비공개 저장소(mdliveData)에 커밋"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(160,144,255,.35);background:rgba(160,144,255,.1);color:#a090ff">🐙</button>
                  <!-- 공개 커밋 (md-viewer GitHub) -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvPushPublic(this)"
                      title="공개 저장소(md-viewer)에 커밋"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(106,247,176,.35);background:rgba(106,247,176,.1);color:#6af7b0">📤</button>
                  <!-- 이동 -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvMoveFile(this)"
                      title="파일 이동 (로컬 폴더)"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.05);color:var(--tx3)">↗</button>
                  <!-- 삭제 -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvDeleteFile(this)"
                      title="파일 삭제 (로컬)"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(247,106,106,.3);background:rgba(247,106,106,.08);color:#f76a6a">🗑</button>
                </div>`;
            });
            html += `</div></div>`;
        });

        list.innerHTML = html;

        /* 공개설정 로컬: 폴더 접기/잠금 바인딩 및 잠금 상태 복원 */
        (function applyPvsFolderLocks() {
            const PVS_LOCKED_KEY = 'mdpro_pvs_locked_folders';
            function getLocked() {
                try {
                    const raw = localStorage.getItem(PVS_LOCKED_KEY);
                    const arr = raw ? JSON.parse(raw) : [];
                    return new Set(Array.isArray(arr) ? arr : []);
                } catch (e) { return new Set(); }
            }
            function setLocked(set) {
                try { localStorage.setItem(PVS_LOCKED_KEY, JSON.stringify([...set])); } catch (e) {}
            }
            list.querySelectorAll('.pvs-local-group').forEach(groupEl => {
                const path = groupEl.dataset.path;
                const hdr = groupEl.querySelector('.pvs-local-group-hdr');
                const body = groupEl.querySelector('.pvs-local-group-body');
                if (!hdr || !body) return;
                const toggle = hdr.querySelector('.ft-toggle');
                const lockSpan = hdr.querySelector('.ft-folder-lock');
                const lockedSet = getLocked();
                if (path && lockedSet.has(path)) {
                    groupEl.classList.add('collapsed');
                    if (toggle) toggle.textContent = '▸';
                    if (lockSpan) lockSpan.classList.add('ft-folder-lock-on');
                }
                hdr.addEventListener('click', function(e) {
                    if (e.target.closest('.ft-folder-lock') || e.target.closest('button')) return;
                    groupEl.classList.toggle('collapsed');
                    if (toggle) toggle.textContent = groupEl.classList.contains('collapsed') ? '▸' : '▾';
                });
                if (lockSpan) lockSpan.addEventListener('click', function(e) {
                    e.stopPropagation();
                    const set = getLocked();
                    if (set.has(path)) {
                        set.delete(path);
                        lockSpan.classList.remove('ft-folder-lock-on');
                    } else {
                        set.add(path);
                        groupEl.classList.add('collapsed');
                        if (toggle) toggle.textContent = '▸';
                        lockSpan.classList.add('ft-folder-lock-on');
                    }
                    setLocked(set);
                });
            });
        })();
    }

    /* ── 공개노트 로컬 폴더를 탐색기에서 열기 ── */
    function _pvOpenLocalDir() {
        if (!_pvDirHandle) { App._toast('⚠ 폴더를 먼저 선택하세요'); return; }
        /* 브라우저 보안 정책 상 직접 탐색기 실행 불가.
           폴더 이름과 경로를 알려주고 선택을 유도 */
        const name = _pvFolderName || _pvDirHandle.name || '?';
        App._toast('📂 폴더: ' + name + ' — 탐색기에서 해당 폴더를 찾아 여세요');
    }

    /* ── 로컬 폴더 새로고침 ── */
    async function _pvRefresh() {
        if (!_pvDirHandle) {
            App._toast('⚠ 폴더가 선택되지 않았습니다');
            return;
        }
        const ok = await _pvRequestPermission();
        if (!ok) { App._toast('⚠ 폴더 접근 권한이 필요합니다'); return; }
        App._toast('⟳ 스캔 중…');
        await _pvSync();
        _renderLocalFiles();
    }

    /* ── 로컬 파일 에디터로 열기 ── */
    /* btnOrRow: .pvs-local-item 행 자체 또는 그 안의 요소 */
    function _pvOpenFile(btnOrRow) {
        const row  = btnOrRow?.closest ? (btnOrRow.closest('.pvs-local-item') || btnOrRow) : btnOrRow;
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다: ' + path); return; }
        if (f.content === null || f.content === undefined) {
            App._toast('⚠ 내용을 읽을 수 없는 파일입니다');
            return;
        }
        if (typeof TM !== 'undefined') {
            TM.newTab({ title: name, content: f.content, path: f.path });
        } else if (typeof App !== 'undefined') {
            const ed = document.getElementById('editor');
            if (ed) { ed.value = f.content; App.render(); }
        }
        App._toast('📝 열기: ' + name);
    }

    /* ── 폴더 경로 → FileSystemDirectoryHandle 탐색 헬퍼 ── */
    /* create=true 이면 경로 상의 폴더가 없어도 생성하면서 진행 */
    async function _pvGetDirHandle(folderPath, create = false) {
        let h = _pvDirHandle;
        if (!folderPath) return h;
        const parts = folderPath.split('/');
        for (const part of parts) {
            if (!part) continue;
            h = await h.getDirectoryHandle(part, { create });
        }
        return h;
    }

    /* ── 파일 내용 헬퍼 ── */
    async function _pvGetContent(path) {
        /* 1) 이미 스캔된 파일에서 가져오기 (빈 문자열도 유효) */
        const cached = _pvFiles.find(x => x.path === path);
        if (cached && cached.content !== null && cached.content !== undefined) {
            return cached.content;
        }
        /* 2) dirHandle 통해 직접 읽기 */
        if (!_pvDirHandle) throw new Error('폴더 핸들 없음 — 폴더를 다시 선택하세요');
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('읽기 권한이 거부되었습니다');
        } catch(e) { /* 이미 granted인 경우 에러 무시 */ }
        const parts = path.split('/');
        let h = _pvDirHandle;
        for (let i = 0; i < parts.length - 1; i++) {
            h = await h.getDirectoryHandle(parts[i]);
        }
        const fileH = await h.getFileHandle(parts[parts.length - 1]);
        const file  = await fileH.getFile();
        return file.text();
    }

    /* ── 비공개 커밋 (mdliveData GH 저장소) ── */
    async function _pvPushPrivate(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!GH.isConnected()) { App._toast('⚠ GH(mdliveData) 연결 설정이 필요합니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const origTxt = btn.textContent;
        btn.textContent = '⟳'; btn.disabled = true;
        try {
            /* 권한 확인 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('폴더 읽기 권한이 필요합니다');

            const content = await _pvGetContent(path);
            if (content === null || content === undefined) throw new Error('파일 내용을 읽을 수 없습니다');

            const ghCfg  = GH.cfg;
            const base   = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const ghPath = base + name;

            let sha = null;
            try {
                const info = await fetch(
                    `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(ghPath)}?ref=${ghCfg.branch}`,
                    { headers: { 'Authorization': `token ${ghCfg.token}`, 'Accept': 'application/vnd.github.v3+json' } }
                ).then(r => r.ok ? r.json() : null);
                if (info?.sha) sha = info.sha;
            } catch(e) {}

            const b64  = btoa(unescape(encodeURIComponent(content)));
            const body = { message: `Upload: ${name}`, content: b64, branch: ghCfg.branch };
            if (sha) body.sha = sha;

            const res = await fetch(
                `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(ghPath)}`,
                {
                    method : 'PUT',
                    headers: {
                        'Authorization': `token ${ghCfg.token}`,
                        'Accept': 'application/vnd.github.v3+json',
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(body),
                }
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(`GitHub ${res.status}: ${err.message || res.statusText}`);
            }
            btn.textContent = origTxt; btn.disabled = false;
            App._toast(`🐙 비공개 커밋 완료: ${name}`);
        } catch(e) {
            btn.textContent = origTxt; btn.disabled = false;
            App._toast('❌ 비공개 커밋 실패: ' + e.message);
        }
    }

    /* ── 공개 커밋 (md-viewer GitHub 저장소) ── */
    async function _pvPushPublic(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn?.closest?.('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); App._toast('⚠ md-viewer 저장소 미설정'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const origTxt = (btn && btn.textContent) || '📤';
        if (btn) { btn.textContent = '⟳'; btn.disabled = true; }
        try {
            /* 권한 확인 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('폴더 읽기 권한이 필요합니다');

            const content  = await _pvGetContent(path);
            if (content === null || content === undefined) throw new Error('파일 내용을 읽을 수 없습니다');

            const filePath = 'docs/' + name;
            let sha = null;
            try { const ex = await _getFile(filePath); if (ex?.sha) sha = ex.sha; } catch(e) {}

            await _putFile(filePath, content, `Publish: ${name}`, sha);
            if (btn) { btn.textContent = origTxt; btn.disabled = false; }

            const link = _makeLink(filePath);
            navigator.clipboard.writeText(link).catch(() => {});
            App._toast(`📤 공개 커밋 완료: ${name}  🔗링크 복사됨`);
        } catch(e) {
            if (btn) { btn.textContent = origTxt; btn.disabled = false; }
            App._toast('❌ 공개 커밋 실패: ' + e.message);
        }
    }

    /* ── 이동 모달 UI (PVShare 전용) ── */
    function _pvShowMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-move-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-move-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9600;background:rgba(0,0,0,.68);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 파일 이동</span>
                    <button id="pvmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_escL(fileName)}</b>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="pvmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvmov-close').onclick  = () => close(null);
            document.getElementById('pvmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvmov-ok').onclick = () => {
                close(document.getElementById('pvmov-dest').value);
            };
        });
    }

    /* ── 로컬 파일 이동 (파일시스템 직접 이동) ── */
    async function _pvMoveFile(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다'); return; }

        /* 이동 가능한 폴더 목록 수집 — 모든 상위 경로 + isDir 빈폴더 포함 */
        const currentFolder = f.folder || '';
        const folderSet = new Set(['']);  /* 루트 항상 포함 */
        _pvFiles.forEach(x => {
            const parts = (x.folder || '').split('/');
            let acc = '';
            for (const p of parts) {
                if (!p) continue;
                acc = acc ? acc + '/' + p : p;
                folderSet.add(acc);
            }
            if (x.isDir) folderSet.add(x.path);
        });

        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet]
            .filter(p => p !== '' && p !== currentFolder)
            .sort()
            .forEach(folderPath => {
                const depth = (folderPath.match(/\//g) || []).length;
                const label = '📂 ' + '  '.repeat(depth) + folderPath.split('/').pop() + '  (' + folderPath + ')';
                folderOptions.push({ label, value: folderPath });
            });

        const destFolder = await _pvShowMoveModal(name, folderOptions);
        if (destFolder === null) return; /* 취소 */

        const destPath = destFolder ? destFolder + '/' + name : name;
        if (destPath === path) { App._toast('ℹ 같은 폴더입니다'); return; }

        const origTxt = btn.textContent;
        btn.textContent = '⟳'; btn.disabled = true;
        try {
            /* 쓰기 권한 요청 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 원본 파일 내용 읽기 */
            const content = await _pvGetContent(path);

            /* 대상 폴더 핸들 */
            const destDirH = await _pvGetDirHandle(destFolder);

            /* 대상 위치에 파일 쓰기 */
            const newFH = await destDirH.getFileHandle(name, { create: true });
            const wr    = await newFH.createWritable();
            await wr.write(content);
            await wr.close();

            /* 원본 삭제 */
            const srcDirH = await _pvGetDirHandle(f.folder || '');
            await srcDirH.removeEntry(name);

            /* 목록 재스캔 & UI 갱신 */
            await _pvSync();
            _renderLocalFiles();
            App._toast(`✅ "${name}" → "${destFolder || '루트'}" 이동 완료`);
        } catch(e) {
            btn.textContent = origTxt; btn.disabled = false;
            App._toast('❌ 이동 실패: ' + e.message);
        }
    }

    /* ── 로컬 파일 삭제 (파일시스템 + 목록 갱신) ── */
    async function _pvDeleteFile(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다'); return; }

        /* DelConfirm 모달 사용 */
        DelConfirm.show({
            name,
            path,
            type: 'local',
            onConfirm: async () => {
                try {
                    const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
                    if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

                    /* 부모 폴더 핸들 탐색 */
                    const parentH = await _pvGetDirHandle(f.folder || '');
                    await parentH.removeEntry(name);

                    /* 메모리 목록 즉시 갱신 */
                    _pvFiles = _pvFiles.filter(x => x.path !== path);
                    _renderLocalFiles();
                    App._toast(`🗑 "${name}" 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    function _escQL(s) { return String(s).replace(/'/g, "\\'").replace(/"/g, '&quot;'); }
    function _escL(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    /* ── Clone 안내 모달 ── */
    /* ── Clone 안내 모달 ── */
    function _cloneModal() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { App._toast('⚠ 저장소 미설정'); return; }
        const cloneUrl = `https://github.com/${vcfg.repo}.git`;

        navigator.clipboard.writeText(cloneUrl).catch(() => {});

        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid rgba(160,144,255,.35);border-radius:12px;
            padding:20px 22px;max-width:460px;width:100%;box-shadow:0 12px 50px rgba(0,0,0,.7)">
          <div style="font-size:13px;font-weight:700;color:#a090ff;margin-bottom:10px">📋 Clone URL 복사됨</div>
          <div style="font-size:11px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
            터미널에서 아래 명령으로 로컬에 Clone하세요:
          </div>
          <div style="background:var(--bg3);border:1px solid var(--bd);border-radius:6px;
              padding:9px 12px;font-family:var(--fm);font-size:11px;color:#a090ff;
              margin-bottom:14px;word-break:break-all;user-select:all">
            git clone ${cloneUrl}
          </div>
          <div style="font-size:10.5px;color:var(--tx3);margin-bottom:14px;line-height:1.6">
            Clone 후 <b style="color:var(--tx2)">로컬 폴더 열기</b>로 해당 폴더를 선택하면<br>
            Pull / Push로 GitHub와 동기화할 수 있습니다.
          </div>
          <div style="background:rgba(247,201,106,.1);border:1px solid rgba(247,201,106,.3);
              border-radius:6px;padding:8px 12px;margin-bottom:14px;
              display:flex;align-items:center;gap:10px">
            <div style="flex:1;font-size:10.5px;color:#f7c96a;line-height:1.6">
              📂 <b>폴더 찾기</b> — 해당 폴더에서 <code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px">cmd</code>를 실행하여 이 코드를 실행하세요 (자동복사됩니다)
            </div>
            <button id="pvs-clone-folder-btn"
                style="padding:5px 12px;border-radius:5px;border:1px solid rgba(247,201,106,.4);
                    background:rgba(247,201,106,.12);color:#f7c96a;font-size:11px;
                    cursor:pointer;white-space:nowrap;flex-shrink:0">
                📂 폴더 찾기</button>
          </div>
          <div style="display:flex;justify-content:flex-end">
            <button id="pvs-clone-close" style="padding:6px 16px;border-radius:6px;
                border:1px solid var(--bd);background:var(--bg3);
                color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
          </div>
        </div>`;
        document.body.appendChild(ov);
        App._toast('📋 Clone URL 복사됨: ' + cloneUrl);

        document.getElementById('pvs-clone-close').onclick = () => ov.remove();
        ov.onclick = e => { if (e.target === ov) ov.remove(); };

        /* 폴더 찾기 — 파일 선택창으로 폴더 열기 */
        document.getElementById('pvs-clone-folder-btn').onclick = () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.webkitdirectory = true;
            input.onchange = () => {
                if (input.files.length) {
                    const path = input.files[0].webkitRelativePath.split('/')[0];
                    App._toast(`📂 폴더 선택됨: ${path} — 로컬 탭에서 이 폴더를 열기하세요`);
                    ov.remove();
                    /* FM의 폴더 선택 연결 */
                    if (typeof FM !== 'undefined') FM.selectFolder();
                }
            };
            input.click();
        };
    }

    /* ── Clone URL 복사 (구형, 하위 호환) ── */
    function _clone() { _cloneModal(); }

    /* ── 새 파일 ── */
    /* ── 탭 분기: 로컬 vs GitHub ── */
    function _dispatchNewFile()   { _activeTab === 'local' ? _pvNewFile()   : _newFile(); }
    function _dispatchNewFolder() { _activeTab === 'local' ? _pvNewFolder() : _newFolder(); }

    /* ══════════════════════════════════════════════════
       PVShare 로컬 폴더 파일/폴더 생성 (FM 방식 차용)
    ══════════════════════════════════════════════════ */

    /* ── 특정 폴더 안에 새 하위 폴더 만들기 (폴더 헤더 📁+ 버튼) ── */
    async function _pvCreateFolderIn(parentPath) {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* parentPath 를 기본 선택한 채 폴더 이름 입력 모달 */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            const parts = (f.folder || '').split('/');
            let acc = '';
            for (const p of parts) { if (!p) continue; acc = acc ? acc + '/' + p : p; folderSet.add(acc); }
            if (f.isDir) folderSet.add(f.path);
        });
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const result = await _pvShowNewFolderModal(parentOptions, parentPath);
        if (!result) return;

        const { parentVal, name } = result;
        if (!name.trim()) return;
        const safe  = name.trim().replace(/[/\\:*?"<>|]/g, '_');
        const where = parentVal ? parentVal + '/' + safe : safe;

        try {
            const parentDirH = await _pvGetDirHandle(parentVal, true);
            const newDirH = await parentDirH.getDirectoryHandle(safe, { create: true });
            /* .gitkeep 생성 */
            try {
                const kh = await newDirH.getFileHandle('.gitkeep', { create: true });
                const kw = await kh.createWritable();
                await kw.write(''); await kw.close();
            } catch(e) {}
            App._toast('📁 "' + where + '" 폴더 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 특정 폴더에 새 파일 만들기 (폴더 헤더 + 버튼) ── */
    async function _pvCreateFileInFolder(folderPath) {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* folderPath 를 기본 위치로 선택한 채 모달 열기 */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            const parts = (f.folder || '').split('/');
            let acc = '';
            for (const p of parts) { if (!p) continue; acc = acc ? acc + '/' + p : p; folderSet.add(acc); }
            if (f.isDir) folderSet.add(f.path);
        });
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        /* 모달 표시 — folderPath 를 기본 선택값으로 */
        const chosen = await _pvShowNewFileModal(folderOptions, folderPath);
        if (!chosen) return;

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe  = fname.replace(/[/\:*?"<>|]/g, '_');
        const where = folderVal ? folderVal + '/' + safe : safe;

        try {
            const destDirH = await _pvGetDirHandle(folderVal, true);
            const fh = await destDirH.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('# ' + safe.replace(/\.md$/i,'') + '\n\n내용을 입력하세요.\n');
            await wr.close();
            App._toast('📄 "' + where + '" 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 파일 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 파일 생성 모달 ── */
    async function _pvNewFile() {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 — 버튼 클릭 직후(사용자 제스처 컨텍스트) */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* 폴더 목록 수집 (isDir 빈 폴더 포함) */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            if (f.folder) folderSet.add(f.folder);
            if (f.isDir)  folderSet.add(f.path);   /* 빈 폴더도 선택 가능 */
        });
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const chosen = await _pvShowNewFileModal(folderOptions);
        if (!chosen) return;

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[/\\:*?"<>|]/g, '_');
        const where = folderVal ? folderVal + '/' + safe : safe;

        try {
            /* create=true: 대상 폴더가 없으면 생성 */
            const destDirH = await _pvGetDirHandle(folderVal, true);
            const fh = await destDirH.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('# ' + safe.replace(/\.md$/i,'') + '\n\n내용을 입력하세요.\n');
            await wr.close();

            App._toast('📄 "' + where + '" 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 파일 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 폴더 생성 모달 ── */
    async function _pvNewFolder() {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 — 버튼 클릭 직후(사용자 제스처 컨텍스트) */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* 폴더 목록 수집 (isDir 빈 폴더 포함) */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            if (f.folder) folderSet.add(f.folder);
            if (f.isDir)  folderSet.add(f.path);   /* 빈 폴더도 상위로 선택 가능 */
        });
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const result = await _pvShowNewFolderModal(parentOptions);
        if (!result) return;

        const { parentVal, name } = result;
        const safe  = name.replace(/[/\\:*?"<>|]/g, '_');
        const where = parentVal ? parentVal + '/' + safe : safe;

        try {
            /* create=true: 부모 경로가 없어도 생성 */
            const parentDirH = await _pvGetDirHandle(parentVal, true);
            const newDirH = await parentDirH.getDirectoryHandle(safe, { create: true });

            /* .gitkeep 생성 (빈 폴더 Git 추적용) */
            try {
                const kh = await newDirH.getFileHandle('.gitkeep', { create: true });
                const kw = await kh.createWritable();
                await kw.write('');
                await kw.close();
            } catch(e) {}

            App._toast('📁 "' + where + '" 폴더 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 파일 모달 UI (FM._showNewFileModal 방식 차용) ── */
    function _pvShowNewFileModal(folderOptions, defaultFolder) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-newfile-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-newfile-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9700;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">💻 새 파일 만들기 (로컬)</span>
                    <button id="pvnf-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (저장 폴더)</label>
                    <select id="pvnf-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => '<option value="' + o.value + '"' + (defaultFolder !== undefined && o.value === defaultFolder ? ' selected' : '') + '>' + o.label + '</option>').join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">파일 이름 (확장자 없으면 .md 자동)</label>
                    <input id="pvnf-name" type="text" value="새파일.md" autocomplete="off"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvnf-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvnf-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('pvnf-name');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvnf-close').onclick   = () => close(null);
            document.getElementById('pvnf-cancel').onclick  = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvnf-ok').onclick = () => {
                const filename  = nameInput.value.trim();
                if (!filename) { nameInput.focus(); return; }
                const folderVal = document.getElementById('pvnf-folder').value;
                close({ folderVal, filename });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('pvnf-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 로컬 새 폴더 모달 UI ── */
    function _pvShowNewFolderModal(parentOptions, defaultParent) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-newfolder-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-newfolder-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9700;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">💻 새 폴더 만들기 (로컬)</span>
                    <button id="pvnd-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (부모 폴더)</label>
                    <select id="pvnd-parent" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${parentOptions.map(o => '<option value="' + o.value + '">' + o.label + '</option>').join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">폴더 이름</label>
                    <input id="pvnd-name" type="text" value="새폴더" autocomplete="off"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvnd-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvnd-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('pvnd-name');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvnd-close').onclick  = () => close(null);
            document.getElementById('pvnd-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvnd-ok').onclick = () => {
                const name = nameInput.value.trim();
                if (!name) { nameInput.focus(); return; }
                const parentVal = document.getElementById('pvnd-parent').value;
                close({ parentVal, name });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('pvnd-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ─────────────────────────────────────────────────── */
    /* GitHub 탭 새 파일/폴더 (기존 유지) */
    /* ─────────────────────────────────────────────────── */
    async function _newFile() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const name = prompt('새 파일명 (예: docs/새파일.md):','docs/새파일.md');
        if (!name) return;

        try {
            _setStatus('생성 중…');
            let sha = null;
            try { const ex = await _getFile(name); sha = ex.sha; } catch(e) {}
            await _putFile(name, '# 새 문서\n\n내용을 입력하세요.\n', `Create: ${name}`, sha);
            _setStatus('');
            _loadList();
            App._toast('📄 파일 생성: ' + name);
        } catch(e) {
            _setStatus('오류');
            alert('생성 실패: ' + e.message);
        }
    }

    /* ── 새 폴더 (.gitkeep) ── */
    async function _newFolder() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const name = prompt('새 폴더명 (예: docs/강의자료):','docs/');
        if (!name) return;

        const keepPath = name.replace(/\/$/, '') + '/.gitkeep';
        try {
            _setStatus('생성 중…');
            await _putFile(keepPath, '', `Create folder: ${name}`, null);
            _setStatus('');
            _loadList();
            App._toast('📁 폴더 생성: ' + name);
        } catch(e) {
            _setStatus('오류');
            alert('폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 파일/폴더 삭제 ── */
    async function _deleteItem(btn) {
        const path = btn.dataset.path;
        const type = btn.dataset.type;
        const name = btn.dataset.name;
        const sha  = btn.dataset.sha;

        if (!confirm(`"${name}"을(를) 삭제하시겠습니까?`)) return;

        try {
            _setStatus('삭제 중…');
            if (type === 'dir') {
                /* 폴더: 하위 파일 전체 가져와서 Trees API로 삭제 */
                const items = await _api(`/git/trees/${_loadCfg()?.branch || 'main'}?recursive=1`);
                const tree  = (items.tree || []).filter(f => f.type === 'blob' && f.path.startsWith(path + '/'));
                await _deleteFolderContents(path, tree);
            } else {
                await _deleteFile(path, sha, `Delete: ${name}`);
            }
            _setStatus('');
            _loadList();
            App._toast(`🗑 삭제: ${name}`);
        } catch(e) {
            _setStatus('오류');
            alert('삭제 실패: ' + e.message);
        }
    }

    /* ── 파일/폴더 이동 ── */
    async function _moveFile(btn) {
        const path = btn.dataset.path;
        const type = btn.dataset.type;
        const name = path.split('/').pop();

        const newPath = prompt('이동할 경로 (전체 경로 입력):', path);
        if (!newPath || newPath === path) return;

        try {
            _setStatus('이동 중…');
            if (type === 'dir') {
                App._toast('⚠ 폴더 이동은 지원되지 않습니다. 파일을 직접 이동해 주세요.');
                _setStatus('');
                return;
            }
            /* 파일: 새 경로에 쓰고 기존 경로 삭제 */
            const oldFile = await _getFile(path);
            const content = decodeURIComponent(escape(atob(oldFile.content.replace(/\n/g,''))));
            let newSha = null;
            try { const ex = await _getFile(newPath); newSha = ex.sha; } catch(e) {}
            await _putFile(newPath, content, `Move: ${name} → ${newPath}`, newSha);
            await _deleteFile(path, oldFile.sha, `Move (cleanup): ${name}`);
            _setStatus('');
            _loadList();
            App._toast(`↗ 이동 완료: ${path} → ${newPath}`);
        } catch(e) {
            _setStatus('오류');
            alert('이동 실패: ' + e.message);
        }
    }

    /* ── GH 파일행 📤 버튼에서 직접 push ── */
    async function quickPush({ name, content }) {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) {
            if (confirm('md-viewer 저장소가 설정되지 않았습니다. 지금 설정하시겠습니까?')) {
                _showSettings();
            }
            return;
        }

        const safeName = name.replace(/[^a-zA-Z0-9가-힣._-]/g,'_').replace(/\.md$/i,'') + '.md';

        /* prompt 대신 전용 모달 — 파일명이 항상 보임 */
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9350;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:16px';
            ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid rgba(88,200,248,.3);
                border-radius:14px;padding:22px 24px;max-width:420px;width:100%;
                box-shadow:0 12px 50px rgba(0,0,0,.7)">
                <div style="font-size:13px;font-weight:700;color:#58c8f8;margin-bottom:4px">
                    📤 md-viewer에 Push</div>
                <div style="font-size:11px;color:var(--tx3);margin-bottom:14px">
                    <span style="color:var(--tx2)">${_esc(vcfg.repo)}</span>
                    의 <code style="color:#a090ff">docs/</code> 폴더에 저장됩니다.
                </div>
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:5px">
                    저장 파일명</label>
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:16px">
                    <span style="font-size:12px;color:var(--tx3);flex-shrink:0">docs/</span>
                    <input id="qp-fname" type="text" value="${safeName}"
                        style="flex:1;background:var(--bg3);border:1px solid var(--bd);
                            border-radius:6px;color:var(--tx);font-size:12px;
                            padding:7px 10px;outline:none;box-sizing:border-box"
                        oninput="document.getElementById('qp-preview').textContent=this.value">
                </div>
                <div style="font-size:10px;color:var(--tx3);margin-bottom:14px;
                    padding:7px 10px;background:var(--bg3);border-radius:6px">
                    🔗 예상 링크:
                    <span id="qp-preview" style="color:#a090ff;word-break:break-all;font-family:var(--fm)">
                        ${safeName}
                    </span>
                </div>
                <div id="qp-status" style="font-size:11px;color:#6af7b0;margin-bottom:10px;display:none"></div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="qp-cancel" style="padding:7px 16px;border-radius:6px;
                        border:1px solid var(--bd);background:var(--bg3);
                        color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="qp-ok" style="padding:7px 18px;border-radius:6px;border:none;
                        background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">
                        ⬆ Push</button>
                </div>
            </div>`;
            document.body.appendChild(ov);
            setTimeout(() => {
                const inp = document.getElementById('qp-fname');
                if (inp) { inp.focus(); inp.select(); }
            }, 40);

            const close = () => { ov.remove(); resolve(); };
            document.getElementById('qp-cancel').onclick = close;
            ov.onclick = (e) => { if (e.target === ov) close(); };

            document.getElementById('qp-ok').onclick = async () => {
                const fname = document.getElementById('qp-fname').value.trim();
                if (!fname) { alert('파일명을 입력하세요'); return; }
                const filePath = 'docs/' + fname;
                const okBtn    = document.getElementById('qp-ok');
                const statusEl = document.getElementById('qp-status');

                okBtn.textContent = '⟳ Push 중…'; okBtn.disabled = true;
                statusEl.style.display = '';
                statusEl.textContent = `docs/${fname} 에 저장 중…`;

                try {
                    let sha = null;
                    try { const ex = await _getFile(filePath); sha = ex.sha; } catch(e) {}
                    await _putFile(filePath, content, `Publish: ${fname}`, sha);
                    const link = _makeLink(filePath);
                    statusEl.textContent = '✅ Push 완료!';
                    App._toast('✅ md-viewer Push 완료');
                    setTimeout(() => { ov.remove(); _showLinkResult(link, fname); resolve(); }, 800);
                    /* 관리 창이 열려 있으면 목록 새로고침 */
                    if (document.getElementById('pvs-list')) _loadList('docs');
                } catch(e) {
                    okBtn.textContent = '⬆ Push'; okBtn.disabled = false;
                    statusEl.style.color = '#f76a6a';
                    statusEl.textContent = '❌ ' + e.message;
                }
            };
        });
    }

    /* ── 링크 결과 모달 ── */
    function _showLinkResult(url, title) {
        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9300;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid rgba(106,247,176,.35);
            border-radius:14px;padding:24px 26px;max-width:460px;width:100%;
            box-shadow:0 12px 50px rgba(0,0,0,.7)">
            <div style="font-size:14px;font-weight:700;color:#6af7b0;margin-bottom:6px">
                ✅ 공유 링크 발급 — ${_esc(title)}</div>
            <div style="font-size:11px;color:var(--tx3);margin-bottom:12px">
                링크를 복사해 공유하세요. 문서를 업데이트해도 같은 링크로 최신 내용이 표시됩니다.
            </div>
            <input id="pvsr-url" type="text" readonly value="${url}" onclick="this.select()"
                style="width:100%;background:var(--bg3);border:1px solid var(--bd);
                    border-radius:6px;color:var(--tx);font-size:11px;
                    padding:8px 10px;outline:none;box-sizing:border-box;
                    font-family:var(--fm);margin-bottom:12px">
            <div style="display:flex;gap:8px">
                <button id="pvsr-copy" style="flex:1;padding:9px;border-radius:7px;border:none;
                    background:var(--ac);color:#fff;font-size:13px;font-weight:700;cursor:pointer">
                    📋 링크 복사</button>
                <a href="${url}" target="_blank" rel="noopener noreferrer"
                    style="flex:1;padding:9px;border-radius:7px;
                        border:1px solid rgba(160,144,255,.4);
                        background:rgba(160,144,255,.1);color:#a090ff;
                        font-size:12px;font-weight:600;cursor:pointer;
                        text-decoration:none;display:flex;align-items:center;
                        justify-content:center;gap:4px">
                    🌐 미리보기</a>
                <button id="pvsr-close" style="padding:9px 14px;border-radius:7px;
                    border:1px solid var(--bd);background:var(--bg3);
                    color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
            </div>
        </div>`;
        document.body.appendChild(ov);
        setTimeout(() => { document.getElementById('pvsr-url')?.select(); }, 40);
        const close = () => ov.remove();
        document.getElementById('pvsr-close').onclick = close;
        ov.onclick = (e) => { if (e.target === ov) close(); };
        document.getElementById('pvsr-copy').onclick = () => {
            navigator.clipboard.writeText(url).then(() => {
                document.getElementById('pvsr-copy').textContent = '✅ 복사됨!';
                setTimeout(close, 1400);
            });
        };
    }

    /* ── 설정 모달 ── */
    /* ── 설정 모달 (로컬 폴더 + md-viewer 저장소 통합) ── */
    function _showSettings() {
        const vcfg      = _loadCfg() || {};
        const curFolder = _pvFolderName || _pvLoadFolderName() || '';

        const ov = document.createElement('div');
        ov.id = 'pvs-settings-overlay';
        ov.style.cssText = 'position:fixed;inset:0;z-index:9400;background:rgba(0,0,0,.78);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:14px;
            padding:0;max-width:460px;width:100%;
            box-shadow:0 12px 50px rgba(0,0,0,.7);overflow:hidden">

          <!-- 헤더 -->
          <div style="display:flex;align-items:center;justify-content:space-between;
              padding:14px 18px 12px;border-bottom:1px solid var(--bd);background:var(--bg3)">
            <span style="font-size:13px;font-weight:700;color:var(--txh)">⚙ 공개노트 설정</span>
            <button id="vcfg-x" style="background:none;border:none;cursor:pointer;
                color:var(--tx3);font-size:18px;padding:0;line-height:1">✕</button>
          </div>

          <div style="padding:18px">

            <!-- ① 로컬 폴더 섹션 -->
            <div style="margin-bottom:18px;padding:12px 14px;
                background:var(--bg3);border:1px solid var(--bd);border-radius:10px">
              <div style="font-size:11px;font-weight:700;color:#58c8f8;margin-bottom:10px;
                  letter-spacing:.5px">💻 로컬 폴더</div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                로컬 PC의 마크다운 폴더를 연결합니다.<br>
                선택한 폴더의 .md 파일이 로컬 탭에 표시됩니다.
              </div>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="flex:1;background:var(--bg4);border:1px solid var(--bd);
                    border-radius:6px;padding:7px 10px;font-size:12px;
                    color:${curFolder ? 'var(--tx)' : 'var(--tx3)'};
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                    id="vcfg-folder-display">
                  ${curFolder ? '📂 ' + curFolder : '선택된 폴더 없음'}
                </div>
                <button id="vcfg-select-folder"
                    style="padding:7px 14px;border-radius:6px;white-space:nowrap;
                        border:1px solid rgba(88,200,248,.4);
                        background:rgba(88,200,248,.1);color:#58c8f8;
                        font-size:12px;cursor:pointer;flex-shrink:0">
                  ${curFolder ? '📂 변경' : '📂 폴더 선택'}
                </button>
              </div>
            </div>

            <!-- ② md-viewer 저장소 섹션 -->
            <div style="margin-bottom:14px;padding:12px 14px;
                background:var(--bg3);border:1px solid var(--bd);border-radius:10px">
              <div style="font-size:11px;font-weight:700;color:#a090ff;margin-bottom:8px;
                  letter-spacing:.5px">🐙 md-viewer GitHub 저장소</div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                노트를 공개할 GitHub 저장소를 설정합니다.<br>
                토큰은 GH 패널 설정에서 자동으로 가져옵니다.
              </div>
              <div style="margin-bottom:10px">
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:4px">
                  저장소 (owner/repo)</label>
                <input id="vcfg-repo" type="text" value="${vcfg.repo || ''}"
                    placeholder="예: myname/my-notes"
                    style="width:100%;background:var(--bg4);border:1px solid var(--bd);
                        border-radius:6px;color:var(--tx);font-size:12px;
                        padding:7px 10px;outline:none;box-sizing:border-box">
                <div style="font-size:10px;color:var(--tx3);margin-top:4px">
                  현재: <span style="color:#a090ff">${vcfg.repo || '미설정'}</span>
                </div>
              </div>
              <div>
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:4px">
                  기본 브랜치</label>
                <input id="vcfg-branch" type="text" value="${vcfg.branch || 'main'}"
                    placeholder="main"
                    style="width:100%;background:var(--bg4);border:1px solid var(--bd);
                        border-radius:6px;color:var(--tx);font-size:12px;
                        padding:7px 10px;outline:none;box-sizing:border-box">
              </div>
            </div>

            <!-- 버튼 -->
            <div style="display:flex;gap:8px;justify-content:flex-end">
              <button id="vcfg-cancel" style="padding:7px 16px;border-radius:6px;
                  border:1px solid var(--bd);background:var(--bg3);
                  color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
              <button id="vcfg-save" style="padding:7px 20px;border-radius:6px;
                  border:none;background:var(--ac);color:#fff;
                  font-size:12px;font-weight:600;cursor:pointer">저장</button>
            </div>

          </div>
        </div>`;

        document.body.appendChild(ov);
        const close = () => ov.remove();

        document.getElementById('vcfg-x').onclick      = close;
        document.getElementById('vcfg-cancel').onclick  = close;
        ov.onclick = (e) => { if (e.target === ov) close(); };

        /* ── 로컬 폴더 선택 버튼 ── */
        document.getElementById('vcfg-select-folder').onclick = async () => {
            const ok = await _pvSelectFolder();
            if (!ok) return;
            const newFolder = _pvFolderName;
            const dispEl    = document.getElementById('vcfg-folder-display');
            const btnEl     = document.getElementById('vcfg-select-folder');
            if (dispEl) {
                dispEl.textContent = newFolder ? '📂 ' + newFolder : '선택된 폴더 없음';
                dispEl.style.color = newFolder ? 'var(--tx)' : 'var(--tx3)';
            }
            if (btnEl) btnEl.textContent = newFolder ? '📂 변경' : '📂 폴더 선택';
            /* 로컬 탭 폴더바도 즉시 업데이트 */
            _renderLocalFiles();
        };

        /* ── 저장 버튼 ── */
        document.getElementById('vcfg-save').onclick = () => {
            const repo   = document.getElementById('vcfg-repo').value.trim();
            const branch = document.getElementById('vcfg-branch').value.trim() || 'main';
            if (repo && !repo.includes('/')) {
                App._toast('⚠ 저장소명은 owner/repo 형식으로 입력하세요');
                return;
            }
            if (repo) {
                _saveCfg({ repo, branch });
                /* pvshare_cfg 및 #pvs-repo-inline 동기화 */
                try {
                    const pvcfg = JSON.parse(localStorage.getItem('pvshare_cfg') || '{}');
                    pvcfg.repo = repo;
                    localStorage.setItem('pvshare_cfg', JSON.stringify(pvcfg));
                    const pi = document.getElementById('pvs-repo-inline');
                    if (pi) pi.value = repo;
                } catch(e) {}
                /* 모달 헤더 저장소명 업데이트 */
                const nameEl = document.getElementById('pvs-repo-name');
                if (nameEl) {
                    nameEl.textContent = repo + ' ↗';
                    nameEl.href = `https://github.com/${repo}`;
                }
                App._toast('✅ md-viewer 저장소 설정 저장됨');
            }
            close();
            _loadList();
            /* 로컬 탭도 새로고침 */
            const localBtn = document.getElementById('pvs-tab-local');
            if (localBtn && localBtn.style.color && localBtn.style.color !== 'var(--tx3)') {
                _renderLocalFiles();
            }
        };

        setTimeout(() => { document.getElementById('vcfg-repo')?.focus(); }, 50);
    }

    /* ── 공개노트 로컬 폴더 선택 (PVShare 전용) ── */
    async function _selectLocalFolder() {
        const ok = await _pvSelectFolder();
        if (ok) _renderLocalFiles();
    }

    /* ── 로컬 파일 열기 (PVShare 전용 → _pvOpenFile 위임) ── */
    function _openLocalFile(btnOrRow) { _pvOpenFile(btnOrRow); }

    /* ── 로컬 파일 Push (PVShare 전용 → _pvPushPublic 위임) ── */
    async function _pushLocalFile(btn) { await _pvPushPublic(btn); }

    /* ── 초기화 ── */
    function refresh() {
        const btn = document.getElementById(BTN_ID);
        if (!btn) return;
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        btn.style.display = tab ? '' : 'none';
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', refresh);
    } else {
        setTimeout(refresh, 300);
    }

    return {
        refresh,
        copy       : openModal,
        openModal,
        quickPush,
        quickPushCurrent: () => {
            const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
            if (!tab) { App._toast('⚠ 열린 문서가 없습니다'); return; }
            const content = document.getElementById('editor')?.value || '';
            return quickPush({ name: tab.title || 'document', content });
        },
        _refresh,
        _pull,
        _pushCurrent,
        _clone,
        _cloneModal,
        _switchTab,
        _newFile,
        _newFolder,
        _dispatchNewFile,
        _dispatchNewFolder,
        _pvNewFile,
        _pvNewFolder,
        _deleteItem,
        _moveFile,
        _copyLink,
        _search,
        _itemClick,
        _showSettings,
        _selectLocalFolder,
        _pvOpenLocalDir,
        _pvCreateFolderIn,
        _pvCreateFileInFolder,
        _openLocalFile,
        _pushLocalFile,
        _pvSelectFolder,
        _pvRefresh,
        _pvOpenFile,
        _pvPushPrivate,
        _pvPushPublic,
        _pvMoveFile,
        _pvDeleteFile,
        _loadList,
        _toggleAutoRefresh,
        _showArIntervalSetting,
    };
})();

