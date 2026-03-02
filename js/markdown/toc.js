/* ═══════════════════════════════════════════════════════════
   TOC — 목차 빌드/이동/삽입
   의존: el (dom.js), US·App (insertTOC 호출 시 — index.js 로드 후)
═══════════════════════════════════════════════════════════ */
const TOC = (() => {
    let obs = null;
    let _clickIgnoreObsUntil = 0;
    function _calcId(rawText) {
        const plain = rawText.replace(/[*_`~\[\]()#]/g, '').trim();
        return 'h-' + plain.toLowerCase()
            .replace(/[^a-z0-9가-힣\s]/g, '')
            .replace(/\s+/g, '-')
            .substring(0, 50);
    }

    function _findHeadingByText(text) {
        const pc = el('preview-container');
        if (!pc) return null;
        const clean = text.replace(/[*_`~\[\]()]/g, '').trim().toLowerCase();
        const all = pc.querySelectorAll('h1,h2,h3');
        for (const h of all) {
            if (h.textContent.trim().toLowerCase() === clean) return h;
        }
        for (const h of all) {
            if (h.textContent.trim().toLowerCase().includes(clean.slice(0, 10))) return h;
        }
        return null;
    }

    function build(md) {
        const list = el('toc-list');
        if (!list) return;
        const hs = []; const cnt = [0, 0, 0];
        md.split('\n').forEach(line => {
            const m = line.match(/^(#{1,3})\s+(.+)/);
            if (!m) return;
            const lv   = m[1].length;
            const text = m[2].replace(/[*_`]/g, '').trim();
            const id   = _calcId(m[2]);
            cnt[lv - 1]++;
            for (let i = lv; i < 3; i++) cnt[i] = 0;
            const num = lv === 1 ? `${cnt[0]}` : lv === 2 ? `${cnt[0]}.${cnt[1]}` : `${cnt[0]}.${cnt[1]}.${cnt[2]}`;
            hs.push({ lv, text, rawText: m[2], id, num });
        });
        if (!hs.length) {
            list.innerHTML = '<div style="padding:12px;color:var(--tx3);font-size:12px">헤딩(#)을 추가하면 자동 생성됩니다.</div>';
            return;
        }
        list.innerHTML = hs.map(h =>
            `<div class="toc-item" data-level="${h.lv}" data-id="${h.id}" data-text="${h.text.replace(/"/g,'&quot;')}" onclick="TOC.go('${h.id}','${h.text.replace(/'/g,'\\&apos;')}')">` +
            `<span class="toc-num">${h.num}</span>` +
            `<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h.text}</span>` +
            `</div>`
        ).join('');
        attachObs();
    }

    function go(id, rawText) {
        _clickIgnoreObsUntil = Date.now() + 450;
        const pc = el('preview-container');
        if (!pc) return;
        let target = pc.querySelector('#' + CSS.escape(id));
        if (!target) target = pc.querySelector('#user-content-' + CSS.escape(id));
        if (!target && rawText) target = _findHeadingByText(rawText);
        if (!target) {
            console.warn('[TOC] 헤딩을 찾을 수 없음:', id, rawText);
            return;
        }
        const containerTop = pc.getBoundingClientRect().top;
        const targetTop    = target.getBoundingClientRect().top;
        pc.scrollTop += (targetTop - containerTop);
        const ed = el('editor');
        if (ed) {
            const lines = ed.value.split('\n');
            const style = window.getComputedStyle(ed);
            const lineHeight = parseFloat(style.lineHeight) || 21;
            const paddingTop = parseFloat(style.paddingTop) || 12;
            const cleanText = (rawText || '').replace(/[*_`~\[\]()#]/g, '').trim().toLowerCase();
            let targetLine = -1;
            for (let i = 0; i < lines.length; i++) {
                const m = lines[i].match(/^#{1,3}\s+(.+)/);
                if (m) {
                    const lineText = m[1].replace(/[*_`~\[\]()#]/g, '').trim().toLowerCase();
                    const lineId = _calcId(m[2]);
                    if (lineId === id || lineText === cleanText || lineText.includes(cleanText.slice(0, 10))) {
                        targetLine = i;
                        break;
                    }
                }
            }
            if (targetLine >= 0) {
                const lineStart = lines.slice(0, targetLine).join('\n').length;
                ed.setSelectionRange(lineStart, lineStart);
                ed.focus();
                const targetScrollTop = paddingTop + targetLine * lineHeight;
                ed.scrollTop = Math.max(0, Math.min(targetScrollTop, ed.scrollHeight - ed.clientHeight));
            }
        }
        document.querySelectorAll('.toc-item').forEach(i => i.classList.remove('active'));
        document.querySelectorAll(`.toc-item[data-id="${id}"]`).forEach(i => i.classList.add('active'));
    }

    function attachObs() {
        if (obs) obs.disconnect();
        const pc = el('preview-container');
        if (!pc) return;
        obs = new IntersectionObserver(entries => {
            if (Date.now() < _clickIgnoreObsUntil) return;
            const intersecting = entries.filter(e => e.isIntersecting);
            if (!intersecting.length) return;
            const topmost = intersecting.reduce((a, b) =>
                a.boundingClientRect.top < b.boundingClientRect.top ? a : b
            );
            const id = topmost.target.id;
            if (!id) return;
            document.querySelectorAll('.toc-item').forEach(i => i.classList.remove('active'));
            const items = document.querySelectorAll(`.toc-item[data-id="${id}"]`);
            items.forEach(i => i.classList.add('active'));
        }, { root: pc, threshold: .1, rootMargin: '0px 0px -60% 0px' });
        pc.querySelectorAll('h1,h2,h3').forEach(h => obs.observe(h));
    }

    function insertTOC() {
        const ed = el('editor');
        const md = ed.value;
        const lines = md.split('\n');
        const hs = []; const cnt = [0, 0, 0];
        lines.forEach(ln => {
            const m = ln.match(/^(#{1,3})\s+(.+)/);
            if (!m) return;
            const lv = m[1].length, text = m[2].replace(/[*_`[\]()]/g, '').trim();
            const id = 'h-' + text.toLowerCase().replace(/[^a-z0-9가-힣\s]/g, '').replace(/\s+/g, '-').substring(0, 50);
            cnt[lv - 1]++; for (let i = lv; i < 3; i++)cnt[i] = 0;
            const num = lv === 1 ? `${cnt[0]}` : lv === 2 ? `${cnt[0]}.${cnt[1]}` : `${cnt[0]}.${cnt[1]}.${cnt[2]}`;
            const indent = '  '.repeat(lv - 1);
            hs.push(`${indent}- [${num}. ${text}](#${id})`);
        });
        if (!hs.length) { alert('헤딩(#)이 없어 목차를 생성할 수 없습니다.'); return; }
        const tocBlock = `## 목차\n\n${hs.join('\n')}\n\n---\n\n`;
        const existing = /^## 목차\n[\s\S]*?---\n\n/m;
        if (existing.test(md)) {
            ed.value = md.replace(existing, tocBlock);
        } else {
            ed.value = tocBlock + md;
        }
        US.snap(); App.render();
    }

    return { build, go, insertTOC };
})();
