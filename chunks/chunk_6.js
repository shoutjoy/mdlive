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

    findKey(e) { if (e.key === 'Enter') this.findNext(); if (e.key === 'Escape') this.toggleFind() },
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
        const escaped = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '\n');
        const withMark = escaped.replace(re, '<mark>$&</mark>');
        layer.innerHTML = withMark;
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
| **단축키 목록** | **Alt+?** | 단축키 표시 (편집 가능) |
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

> \`Alt+?\` → 전체 단축키 목록
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

    const $ = id => document.getElementById(id);

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
            _doInsert(include);
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
