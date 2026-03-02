/* ═══════════════════════════════════════════════════════════
   MARKDOWN PARSER — mdRender, splitPages, parseSlideContent
   의존: marked (전역), el 없음
═══════════════════════════════════════════════════════════ */

function mdRender(md, showFootnotes) {
    try {
        /* ── ~ 이스케이프 전처리 ──────────────────────────────────
           ~~취소선~~, ~취소선~ (공백 경계) 는 유지하고,
           범위 표기용 ~ (면(1~2), 1~2배, A~B 등) 는 \~ 이스케이프.
           marked 9.x GFM 에서 ~ 앞뒤 문자 무관하게 strikethrough 처리하므로
           의도치 않은 취소선을 방지한다.                          */
        const _strikePH = [];
        // 1) ~~...~~ 보호
        md = md.replace(/~~[\s\S]*?~~/g, m => {
            const idx = _strikePH.length; _strikePH.push(m);
            return `\x00STR${idx}\x00`;
        });
        // 2) (공백/줄경계) ~취소선~ → <del>취소선</del> 직접 변환
        //    ※ step4에서 ~text~ 그대로 복원하면 marked가 재처리하므로 HTML 선변환
        md = md.replace(/(^|\s)~([^~\n]+?)~(\s|$)/gm, (m, pre, inner, post) => {
            const idx = _strikePH.length;
            _strikePH.push(`<del>${inner}</del>`);
            return `${pre}\x00STR${idx}\x00${post}`;
        });
        // 3) 나머지 ~ 이스케이프 (범위 표기 등)
        md = md.replace(/~/g, '\\~');
        // 4) 플레이스홀더 복원
        md = md.replace(/\x00STR(\d+)\x00/g, (m, i) => _strikePH[parseInt(i)]);
        /* ── 각주 처리 ── */
        // Process footnotes: highlight [^n] references and collect definitions
        let fnDefs = {}; let fnCounter = 0;
        // Collect footnote definitions [^n]: text
        md = md.replace(/^\[\^([^\]]+)\]:\s*(.+)$/gm, (m, key, text) => { fnDefs[key] = text; return '__FN_DEF_' + key + '__' });
        // Replace inline [^n] with highlighted spans
        md = md.replace(/\[\^([^\]]+)\]/g, (m, key) => {
            fnCounter++;
            return `<sup class="footnote-highlight" title="${fnDefs[key] || ''}">[${fnCounter}]</sup>`;
        });
        // Remove def placeholders (they'll be added to footnotes section)
        md = md.replace(/__FN_DEF_[^_]+__\n?/g, '');
        // ** 사이에 (), [], 등 특수문자가 있으면 marked가 파싱 못하므로 <b>로 선변환
        md = md.replace(/\*\*([^*\n]*[()[\]{}][^*\n]*)\*\*/g, (m, inner) => `<b>${inner}</b>`);
        let html = marked.parse(md || '');
        // Append footnotes section if there are definitions and showFootnotes is not false
        if (Object.keys(fnDefs).length > 0 && showFootnotes !== false) {
            let fnHtml = '<div class="footnotes-section">';
            let i = 1;
            Object.entries(fnDefs).forEach(([k, v]) => { fnHtml += `<div class="footnote-def"><sup>[${i}]</sup> ${v}</div>`; i++ });
            fnHtml += '</div>';
            html += fnHtml;
        }
        return html;
    } catch (e) { return `<p style="color:red">${e.message}</p>`; }
}

function splitPages(md) { const p = md.replace(/\r\n/g, '\n').split(/\n?<div class="page-break"><\/div>\n?/); return p.length ? p : [md] }

function parseSlideContent(slideMd) {
    const raw = (slideMd || '').trim();
    const lines = raw.split('\n');
    let title = '';
    const bullets = [];
    let notes = '';
    let inNotes = false;
    for (const line of lines) {
        if (/^notes:\s*$/i.test(line)) { inNotes = true; continue; }
        if (inNotes) { notes += (notes ? '\n' : '') + line; continue; }
        const h1 = line.match(/^#\s+(.+)$/);
        if (h1) { title = h1[1].trim(); continue; }
        if (/^-\s+/.test(line)) bullets.push(line.replace(/^-\s+/, '').trim());
    }
    return { title, bullets, notes: notes.trim() };
}

function parseMarkdownToSlides(md) {
    const pages = splitPages(md || '');
    return { slides: pages.map(p => parseSlideContent(p)) };
}
