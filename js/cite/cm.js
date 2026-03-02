/* CM — Cite Manager (참고문헌 라이브러리, APA/MLA/Chicago 변환). 의존: el, ins, App, US, dlBlob */
const CM = (() => {
    const KEY = 'mdpro_refs'; let refs = []; let sep = 'blank';// blank|line
    const MANUAL_REF_LOG_KEY = 'mdpro_manual_ref_log';

    function load() { try { refs = JSON.parse(localStorage.getItem(KEY) || '[]') } catch (e) { refs = [] } }
    function save() { try { localStorage.setItem(KEY, JSON.stringify(refs)) } catch (e) { } }
    function loadManual() { try { return JSON.parse(localStorage.getItem(MANUAL_REF_LOG_KEY) || '[]') } catch (e) { return [] } }
    function saveManual(arr) { try { localStorage.setItem(MANUAL_REF_LOG_KEY, JSON.stringify(arr)) } catch (e) { } }

    function setSep(s) {
        sep = s;
        el('sep-blank-btn').classList.toggle('active', s === 'blank');
        el('sep-line-btn').classList.toggle('active', s === 'line');
        const descs = { blank: '현재: 빈 줄로 구분 — 항목 사이에 빈 줄 하나를 넣어 구분하세요.', line: '현재: 엔터(줄바꿈)로 구분 — 각 줄이 하나의 참고문헌으로 처리됩니다.' };
        el('sep-desc').textContent = descs[s];
    }

    function parseAPA(line) {
        line = line.trim(); if (!line || line.length < 10) return null;
        const ym = line.match(/\((\d{4}[a-z]?)\)/); const year = ym ? ym[1] : '?';
        let ap = ym ? line.substring(0, line.indexOf(ym[0])).trim().replace(/,\s*$/, '') : line.split('.')[0];
        const names = ap.split(/,\s*&\s*|;\s*|,\s*(?=[A-Z가-힣])/).map(s => s.trim().split(',')[0].trim()).filter(Boolean);
        let key = names.length === 1 ? `${names[0]}, ${year}` : names.length === 2 ? `${names[0]} & ${names[1]}, ${year}` : `${names[0]} et al., ${year}`;
        return { key, year, author: names[0] || 'Unknown', full: line, id: Date.now() + Math.random(), mla: '', chicago: '' };
    }

    function parse() {
        const raw = el('cite-raw').value; if (!raw.trim()) return;
        let lines;
        if (sep === 'blank') {
            lines = raw.split(/\n[ \t]*\n+/).map(block =>
                block.split('\n').map(l => l.trim()).filter(Boolean).join(' ')
            ).map(l => l.replace(/^\d+[\.\)]\s*/, '')).filter(l => l.length > 10);
        } else {
            lines = raw.split('\n').map(l => l.replace(/^\d+[\.\)]\s*/, '').trim()).filter(l => l.length > 10);
        }
        let added = 0;
        lines.forEach(l => { const p = parseAPA(l); if (p && !refs.find(r => r.full === p.full)) { p.mla = toMLA(p); p.chicago = toChicago(p); refs.push(p); added++ } });
        save();
        el('cite-msg').textContent = added ? `✓ ${added}건 추가됨 (총 ${refs.length}건)` : lines.length ? '이미 존재하거나 파싱 실패' : '빈 줄이 없습니다 — 구분 방식을 확인하세요';
        setTimeout(() => el('cite-msg').textContent = '', 4000);
        renderLib(); renderList('');
    }

    function loadFile(ev) {
        const file = ev.target.files[0]; if (!file) return;
        const reader = new FileReader();
        reader.onload = e => { el('cite-raw').value = e.target.result; };
        reader.readAsText(file, 'utf-8');
        ev.target.value = '';
    }

    function toMLA(ref) {
        const m = ref.full.match(/^(.+?)\.\s*\((\d{4}[a-z]?)\)\.\s*(.+?)\.\s*([^,]+),\s*(\d+)\((\d+)\),\s*([\d–\-]+)/);
        if (m) { const [, authors, year, title, journal, vol, no, pp] = m; return `${expandAuthors(authors)} "${capTitle(title.trim())}" ${journal}, vol. ${vol}, no. ${no}, ${year}, pp. ${pp}.` }
        const fy = ref.year || '?';
        const titlePart = ref.full.replace(/\(.*?\)\./, '').replace(/^[^.]+\.\s*/, '').trim();
        return `${ref.author}. "${titlePart}" ${fy}.`;
    }

    function toChicago(ref) {
        const m = ref.full.match(/^(.+?)\.\s*\((\d{4}[a-z]?)\)\.\s*(.+?)\.\s*([^,]+),\s*(\d+)\((\d+)\),\s*([\d–\-]+)/);
        if (m) { const [, authors, year, title, journal, vol, no, pp] = m; return `${expandAuthors(authors)} ${year}. "${capTitle(title.trim())}" ${journal} ${vol} (${no}): ${pp}.` }
        return `${ref.author}. ${ref.year}. "${ref.full}."`;
    }

    function toVancouver(ref) {
        const m = ref.full.match(/^(.+?)\.\s*\((\d{4}[a-z]?)\)\.\s*(.+?)\.\s*([^,]+),\s*(\d+)\((\d+)\),\s*([\d–\-]+)/);
        if (m) { const [, authors, year, title, journal, vol, no, pp] = m; const au = authors.split(/,\s*&\s*|;\s*/).map(s => s.trim()).join(', '); return `${au}. ${title.trim()}. ${journal}. ${year};${vol}(${no}):${pp}.` }
        return ref.full;
    }

    function expandAuthors(s) { return s.replace(/\s*&\s*/g, ', and ').replace(/,\s*et\s+al\./, 'et al.') }
    function capTitle(t) { return t.replace(/\b(\w)/g, (m, c, i) => i === 0 || '.:!?'.includes(t[i - 1]) ? c.toUpperCase() : m) }

    function convertByStyle(ref, style) {
        if (style === 'mla') return ref.mla || toMLA(ref);
        if (style === 'chicago') return ref.chicago || toChicago(ref);
        if (style === 'vancouver') return toVancouver(ref);
        return ref.full;
    }

    function convertStyle() {
        const to = el('to-style').value;
        const raw = el('conv-input').value.trim();
        if (!raw) { el('conv-output').value = '입력 내용이 없습니다.'; return }
        const p = parseAPA(raw); if (!p) { el('conv-output').value = '파싱 실패 — APA 형식을 확인하세요.'; return }
        p.mla = toMLA(p); p.chicago = toChicago(p);
        el('conv-output').value = convertByStyle(p, to);
        const labels = { apa: 'APA 7', mla: 'MLA 9', chicago: 'Chicago (Author-Date)', vancouver: 'Vancouver' };
        el('conv-label').textContent = `→ ${labels[to]}`;
    }
    function copyConverted() { const v = el('conv-output').value; if (v) navigator.clipboard.writeText(v).then(() => { }).catch(() => { }) }
    function insertConverted() { const v = el('conv-output').value; if (!v) return; const ed = el('editor'), pos = ed.selectionEnd; ins(ed, pos, pos, '\n' + v + '\n'); App.hideModal('cite-modal') }

    function renderList(q) {
        const area = el('cite-list-area');
        const flt = refs.filter(r => !q || r.full.toLowerCase().includes(q.toLowerCase()) || r.key.toLowerCase().includes(q.toLowerCase()));
        if (!flt.length) { area.innerHTML = '<div class="cite-empty">해당 문헌 없음. 추가 탭에서 먼저 입력하세요.</div>'; return }
        area.innerHTML = flt.map(r => `<div class="cite-entry" onclick="CM.toggle('cb_${r.id}')"><input type="checkbox" id="cb_${r.id}" data-id="${r.id}" onchange="CM.upd()" onclick="event.stopPropagation()"><div class="cite-body"><div class="cite-key">${r.key}</div><div class="cite-full" title="${r.full}">${r.full}</div></div></div>`).join('');
        upd();
    }

    function filter() { renderList(el('cite-search').value) }
    function toggle(id) { const cb = el(id); if (cb) { cb.checked = !cb.checked; upd() } }
    function getSel() { return Array.from(document.querySelectorAll('#cite-list-area input:checked')).map(cb => refs.find(r => String(r.id) === cb.dataset.id)).filter(Boolean) }
    function upd() {
        const n = getSel().length;
        el('cite-sc').textContent = `${n}개 선택됨`;
        el('cite-ins-btn').style.display = n > 0 ? '' : 'none';
    }
    function selAll() { document.querySelectorAll('#cite-list-area input[type=checkbox]').forEach(cb => cb.checked = true); upd() }
    function clrSel() { document.querySelectorAll('#cite-list-area input[type=checkbox]').forEach(cb => cb.checked = false); upd() }

    function _addToManualList(entries) {
        const manual = loadManual();
        const seen = new Set(manual.map(r => r.full));
        entries.forEach(r => {
            if (!seen.has(r.full)) {
                seen.add(r.full);
                manual.push({ ...r, id: r.id || Date.now() + Math.random() });
            }
        });
        saveManual(manual);
    }
    function insert() {
        const sel = getSel(); if (!sel.length) return;
        const style = el('cite-style').value; const ed = el('editor'); const pos = ed.selectionStart;
        let text = '';
        if (style === 'inline') text = '(' + sel.map(r => r.key).join('; ') + ')';
        else if (style === 'narrative') text = sel.map(r => `${r.author}(${r.year})`).join('; ');
        else if (style === 'multi') text = '(' + sel.map(r => `${r.author}, ${r.year}`).join('; ') + ')';
        else if (style === 'footnote') {
            let it = '', dt = '\n';
            sel.forEach((r, i) => { const n = Math.floor((ed.value.match(/\[\^\d+\]/g) || []).length / 2) + i + 1; it += `[^${n}]`; dt += `[^${n}]: ${r.full}\n` });
            ed.value = ed.value.substring(0, pos) + it + ed.value.substring(pos) + dt;
            _addToManualList(sel);
            App.render(); US.snap(); App.hideModal('cite-modal'); return;
        }
        ed.value = ed.value.substring(0, pos) + text + ed.value.substring(pos);
        ed.setSelectionRange(pos + text.length, pos + text.length);
        _addToManualList(sel);
        App.render(); US.snap(); App.hideModal('cite-modal');
    }

    function renderLib() {
        el('lib-cnt').textContent = refs.length;
        if (!refs.length) { el('lib-list').innerHTML = '<div class="cite-empty">저장된 참고문헌이 없습니다.</div>'; return }
        el('lib-list').innerHTML = refs.map((r, i) => `<div class="lib-item"><span class="lib-key">${r.key}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px" title="${r.full}">${r.full}</span><span style="font-size:10px;color:var(--tx3);flex-shrink:0;margin:0 4px">${r.mla ? 'MLA✓' : ''}</span><button class="btn-ic" style="color:var(--er);font-size:12px;flex-shrink:0" onclick="CM.del(${i})">✕</button></div>`).join('');
    }

    function del(i) { refs.splice(i, 1); save(); renderLib(); renderList(el('cite-search')?.value || '') }
    function clearAll() { if (!confirm('모든 참고문헌을 삭제하시겠습니까?')) return; refs = []; save(); renderLib(); renderList('') }

    function insertRefSection() {
        const ed = el('editor'); const pos = ed.selectionEnd;
        const list = refs.map((r, i) => `${i + 1}. ${r.full}`).join('\n');
        const block = `\n\n<div class="ref-block">\n\n**참고문헌**\n\n${list}\n\n</div>\n`;
        ed.value = ed.value.substring(0, pos) + block + ed.value.substring(pos); App.render(); US.snap(); App.hideModal('cite-modal');
    }

    function downloadLibTxt() {
        let content = `# 참고문헌 목록 (${new Date().toLocaleDateString()})\n\n`;
        content += `## APA 7\n\n`; refs.forEach((r, i) => { content += `${i + 1}. ${r.full}\n` });
        content += `\n## MLA 9\n\n`; refs.forEach((r, i) => { content += `${i + 1}. ${r.mla || toMLA(r)}\n` });
        content += `\n## Chicago (Author-Date)\n\n`; refs.forEach((r, i) => { content += `${i + 1}. ${r.chicago || toChicago(r)}\n` });
        dlBlob(content, 'references.txt', 'text/plain;charset=utf-8');
    }

    function toAPA7MD(ref) {
        const line = (ref.full || '').replace(/\*/g, '').trim();
        const ym = line.match(/\((\d{4}[a-z]?)\)/);
        const year = ym ? ym[1] : '';
        const doiMatch = line.match(/(?:https:\/\/doi\.org\/|doi:)\s*([^\s.,]+)/i);
        const doi = doiMatch ? 'https://doi.org/' + doiMatch[1].replace(/^https:\/\/doi\.org\//i, '') : '';
        const beforeDoi = doi ? line.substring(0, line.search(/(?:https:\/\/doi\.org\/|doi:)/i)).trim() : line;
        const main = beforeDoi.replace(/\*/g, '').trim();
        const authorPart = main.substring(0, main.indexOf('(')).trim().replace(/\.\s*$/, '');
        const afterYear = main.substring(main.indexOf(')') + 1).trim();
        const titleMatch = afterYear.match(/^\.?\s*(.+?)\s*\.\s*(.+)$/);
        const title = titleMatch ? titleMatch[1].trim() : afterYear;
        const tail = titleMatch ? titleMatch[2].trim() : '';
        const journalMatch = tail.match(/^([^,]+),\s*(\d+)\s*\(\s*(\d+)\s*\)\s*,\s*(?:pp\.\s*)?([\d\s–\-]+)/);
        let journal = '', vol = '', issue = '', pages = '';
        if (journalMatch) {
            journal = journalMatch[1].trim();
            vol = journalMatch[2];
            issue = journalMatch[3];
            pages = journalMatch[4].replace(/\s*[-–]\s*/, '–').trim();
        } else {
            const simple = tail.match(/^([^,]+),\s*(\d+)\s*\(\s*(\d+)\s*\)/);
            if (simple) {
                journal = simple[1].trim();
                vol = simple[2];
                issue = simple[3];
            } else {
                journal = tail;
            }
        }
        const sentenceCase = (s) => {
            if (!s || /[가-힣]/.test(s)) return s;
            return s.toLowerCase().replace(/(^\s*\w|\.\s*\w|!\s*\w|\?\s*\w)/g, m => m.toUpperCase());
        };
        const outTitle = sentenceCase(title);
        const outJournal = journal ? `*${journal}*` : '';
        const outVol = vol ? `*${vol}*` : '';
        const outIssue = issue ? `(${issue})` : '';
        const pagePart = pages ? `, ${pages}` : '';
        const doiPart = doi ? `. ${doi}` : '';
        return `${authorPart}. (${year}). ${outTitle}. ${outJournal}${outJournal && (outVol || outIssue) ? ', ' : ''}${outVol}${outIssue}${pagePart}.${doiPart}`;
    }

    function downloadLibMd() {
        const sorted = [...refs].sort((a, b) => {
            const sa = (a.author || a.key || '').toLowerCase();
            const sb = (b.author || b.key || '').toLowerCase();
            return sa.localeCompare(sb);
        });
        const lines = sorted.map(r => toAPA7MD(r)).filter(Boolean);
        const content = '# References\n\n' + lines.join('\n\n') + '\n';
        dlBlob(content, 'references.md', 'text/markdown;charset=utf-8');
    }

    function loadLibFromMd() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.md,text/markdown,text/plain';
        input.onchange = (ev) => {
            const file = ev.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const text = (e.target.result || '').trim();
                const blocks = text.split(/\n\s*\n+/).map(s => s.replace(/\*/g, '').trim()).filter(s => s.length > 10 && !/^#\s*References?\s*$/i.test(s));
                let added = 0;
                blocks.forEach(block => {
                    const p = parseAPA(block);
                    if (p && !refs.find(r => r.full === p.full)) {
                        p.mla = toMLA(p);
                        p.chicago = toChicago(p);
                        refs.push(p);
                        added++;
                    }
                });
                save();
                renderLib();
                renderList(el('cite-search')?.value || '');
                if (added > 0 && typeof App !== 'undefined' && App._toast) App._toast(`✓ ${added}건 불러옴 (총 ${refs.length}건)`);
            };
            reader.readAsText(file, 'utf-8');
            input.value = '';
        };
        input.click();
    }

    function downloadLib() {
        downloadLibTxt();
    }

    function openLibInNewWindow() {
        if (!refs.length) {
            if (typeof App !== 'undefined' && App._toast) App._toast('저장된 참고문헌이 없습니다.');
            return;
        }
        const sorted = [...refs].sort((a, b) => {
            const sa = (a.author || a.key || '').toLowerCase();
            const sb = (b.author || b.key || '').toLowerCase();
            return sa.localeCompare(sb);
        });
        const lines = sorted.map(r => toAPA7MD(r)).filter(Boolean);
        const md = '# References\n\n' + lines.join('\n\n') + '\n';
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(md, true) : (typeof marked !== 'undefined' ? marked.parse(md) : md.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:var(--er)">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes,resizable=yes');
        if (!w) {
            alert('팝업이 차단되었을 수 있습니다.');
            return;
        }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>참고문헌 목록</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3);flex-wrap:wrap">' +
            '<button type="button" onclick="var p=document.getElementById(\'lib-pv-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'lib-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'lib-pv-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'lib-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">축소</button>' +
            '<span id="lib-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '<button type="button" onclick="var ta=document.getElementById(\'lib-pv-md-src\');if(ta){navigator.clipboard.writeText(ta.value).then(function(){var t=document.getElementById(\'lib-copy-msg\');if(t){t.textContent=\'✓ 양식 포함 복사됨\';setTimeout(function(){t.textContent=\'\';},2000)}})}" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">양식포함복사</button>' +
            '<span id="lib-copy-msg" style="font-size:11px;color:var(--ok)"></span>' +
            '</div>' +
            '<textarea id="lib-pv-md-src" style="display:none"></textarea>' +
            '<div id="lib-pv-content" style="flex:1;min-height:0;overflow:auto;padding:20px;font-size:13px;line-height:1.7">' +
            '<div class="preview-page" style="max-width:720px;margin:0 auto">' + html + '</div></div></body></html>'
        );
        w.document.close();
        const ta = w.document.getElementById('lib-pv-md-src');
        if (ta) ta.value = md;
    }

    function renderManualList() {
        const manual = loadManual();
        const cntEl = document.getElementById('manual-cnt');
        const listEl = document.getElementById('manual-ref-log');
        if (!listEl) return;
        if (cntEl) cntEl.textContent = manual.length;
        if (!manual.length) { listEl.innerHTML = '<div class="cite-empty">인용 삽입 시 선택된 항목이 여기에 추가됩니다.</div>'; return; }
        listEl.innerHTML = manual.map((r, i) => `<div class="lib-item"><span class="lib-key">${r.key}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px" title="${r.full}">${r.full}</span><span style="font-size:10px;color:var(--tx3);flex-shrink:0;margin:0 4px">${r.mla ? 'MLA✓' : ''}</span><button class="btn-ic" style="color:var(--er);font-size:12px;flex-shrink:0" onclick="CM.delManual(${i})">✕</button></div>`).join('');
    }
    function delManual(i) { const m = loadManual(); m.splice(i, 1); saveManual(m); renderManualList(); }
    function clearManual() { if (!confirm('수동참고문헌 목록을 모두 삭제하시겠습니까?')) return; saveManual([]); renderManualList(); }
    function insertRefSectionFromManual() {
        const manual = loadManual(); if (!manual.length) { App._toast('수동참고문헌이 없습니다.'); return; }
        const ed = el('editor'); const pos = ed.selectionEnd;
        const list = manual.map((r, i) => `${i + 1}. ${r.full}`).join('\n');
        const block = `\n\n<div class="ref-block">\n\n**참고문헌**\n\n${list}\n\n</div>\n`;
        ed.value = ed.value.substring(0, pos) + block + ed.value.substring(pos); App.render(); US.snap(); App.hideModal('cite-modal');
    }
    function downloadManual() {
        const manual = loadManual(); if (!manual.length) { App._toast('수동참고문헌이 없습니다.'); return; }
        let content = `# 수동참고문헌 목록 (${new Date().toLocaleDateString()})\n\n`;
        content += `## APA 7\n\n`; manual.forEach((r, i) => { content += `${i + 1}. ${r.full}\n` });
        content += `\n## MLA 9\n\n`; manual.forEach((r, i) => { content += `${i + 1}. ${r.mla || toMLA(r)}\n` });
        content += `\n## Chicago (Author-Date)\n\n`; manual.forEach((r, i) => { content += `${i + 1}. ${r.chicago || toChicago(r)}\n` });
        dlBlob(content, 'manual-references.txt', 'text/plain;charset=utf-8');
    }
    function tab(name) {
        const names = ['add', 'cite', 'convert', 'lib', 'manual', 'search', 'ai-search'];
        document.querySelectorAll('#cite-modal .tr-tab').forEach(t => t.classList.toggle('active', t.getAttribute('data-tab') === name));
        names.forEach(n => { const p = el(`cp-${n}`); if (p) p.classList.toggle('active', n === name); });
        const footer = document.getElementById('cite-ai-search-footer');
        const insBtn = el('cite-ins-btn');
        if (name === 'ai-search') {
            if (footer) footer.style.display = 'flex';
            if (insBtn) insBtn.style.display = 'none';
            if (typeof DeepResearch !== 'undefined') DeepResearch.applyCiteAiSearchPreset();
            setTimeout(() => { el('cite-ai-prompt')?.focus(); if (typeof CiteAiSearchHistory !== 'undefined') CiteAiSearchHistory.renderList(); }, 80);
        } else {
            if (footer) footer.style.display = 'none';
            if (insBtn) insBtn.style.display = '';
        }
        if (name === 'cite') { renderList(el('cite-search')?.value || ''); if (insBtn) insBtn.style.display = 'none'; }
        if (name === 'lib') renderLib();
        if (name === 'manual') renderManualList();
        if (name === 'search') { if (typeof RefSearch !== 'undefined') RefSearch.syncAiPromptVisibility(); setTimeout(() => el('ref-q')?.focus(), 80); }
    }

    function addRaw(apaStr) {
        apaStr = apaStr.trim(); if (!apaStr) return;
        const p = parseAPA(apaStr);
        if (p && !refs.find(r => r.full === p.full)) { p.mla = toMLA(p); p.chicago = toChicago(p); refs.push(p); save(); renderLib(); }
    }

    function open() { load(); renderList(''); renderLib(); el('cite-ins-btn').style.display = 'none' }

    return { load, setSep, parse, loadFile, filter, toggle, getSel, upd, selAll, clrSel, insert, del, clearAll, insertRefSection, downloadLib, downloadLibTxt, downloadLibMd, loadLibFromMd, openLibInNewWindow, renderManualList, delManual, clearManual, insertRefSectionFromManual, downloadManual, convertStyle, copyConverted, insertConverted, tab, open, addRaw };
})();
