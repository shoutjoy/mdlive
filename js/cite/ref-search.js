/* RefSearch — CrossRef / OpenAlex 내장 논문 검색 → js/cite/ref-search.js
   의존: el, CM, ScholarApiKey(선택) */

/* ═══════════════════════════════════════════════════════════
   REF SEARCH — CrossRef / OpenAlex 내장 논문 검색
═══════════════════════════════════════════════════════════ */
const RefSearch = (() => {
    let _loading = false;

    function toAPA(w) {
        if (w._src === 'scholar' && w.full) return w.full;
        let authors = '';
        if (w._src === 'openalex') {
            const au = (w.authorships || []).map(a => a.author?.display_name || '').filter(Boolean);
            if (au.length === 0) authors = 'Unknown';
            else if (au.length <= 5) authors = au.map(fmtName).join(', ');
            else authors = fmtName(au[0]) + ', et al.';
        } else {
            const au = (w.author || []).map(a => {
                if (a.family && a.given) return `${a.family}, ${a.given.trim()[0].toUpperCase()}.`;
                if (a.family) return a.family;
                if (a.name) return a.name;
                return '';
            }).filter(Boolean);
            if (au.length === 0) authors = 'Unknown';
            else if (au.length <= 5) authors = au.join(', ');
            else authors = au[0] + ', et al.';
        }
        const year = w._year || 'n.d.';
        const title = w._title || 'Untitled';
        const journal = w._journal || '';
        const vol = w.volume || w._vol || '';
        const iss = w.issue || w._iss || '';
        const page = w.page || w._page || '';
        const doi = w.DOI || w._doi || '';
        let cite = `${authors} (${year}). ${title}.`;
        if (journal) cite += ` ${journal}`;
        if (vol) cite += `, ${vol}`;
        if (iss) cite += `(${iss})`;
        if (page) cite += `, ${page}`;
        cite += '.';
        if (doi) cite += ` https://doi.org/${doi}`;
        return cite;
    }

    function fmtName(n) {
        if (!n) return '';
        const parts = n.trim().split(/\s+/);
        if (parts.length === 1) return parts[0];
        const last = parts[parts.length - 1];
        const initials = parts.slice(0, -1).map(p => p[0].toUpperCase() + '.').join(' ');
        return `${last}, ${initials}`;
    }

    async function searchCrossRef(q, year) {
        const rows = 10;
        let url = `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=${rows}&select=DOI,title,author,published-print,published-online,container-title,volume,issue,page&mailto=mdpro@editor.app`;
        if (year) url += `&filter=from-pub-date:${year}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('CrossRef 응답 오류');
        const data = await res.json();
        return (data.message?.items || []).map(w => {
            const yr = (w['published-print'] || w['published-online'])?.['date-parts']?.[0]?.[0] || '';
            return {
                _src: 'crossref', _title: (w.title || [''])[0], _year: yr,
                _journal: (w['container-title'] || [])[0] || '',
                _vol: w.volume || '', _iss: w.issue || '', _page: w.page || '',
                DOI: w.DOI || '', author: w.author || [],
                _url: w.DOI ? `https://doi.org/${w.DOI}` : ''
            };
        });
    }

    async function searchOpenAlex(q, year) {
        let url = `https://api.openalex.org/works?search=${encodeURIComponent(q)}&per-page=10&select=id,title,authorships,publication_year,primary_location,biblio,doi,open_access`;
        if (year) url += `&filter=publication_year:>${parseInt(year) - 1}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('OpenAlex 응답 오류');
        const data = await res.json();
        return (data.results || []).map(w => {
            const src = w.primary_location?.source;
            return {
                _src: 'openalex', _title: w.title || '', _year: w.publication_year || '',
                _journal: src?.display_name || '',
                _vol: w.biblio?.volume || '', _iss: w.biblio?.issue || '',
                _page: w.biblio?.first_page ? (w.biblio.first_page + (w.biblio.last_page ? '–' + w.biblio.last_page : '')) : '',
                _doi: w.doi ? w.doi.replace('https://doi.org/', '') : '',
                DOI: w.doi ? w.doi.replace('https://doi.org/', '') : '',
                authorships: w.authorships || [],
                _oa: w.open_access?.is_oa || false,
                _url: w.doi || ''
            };
        });
    }

    async function searchScholarSerpApi(q, year) {
        const apiKey = typeof ScholarApiKey !== 'undefined' ? ScholarApiKey.get() : '';
        if (!apiKey) throw new Error('Scholar API 키가 없습니다. 설정에서 SerpAPI 키를 입력·저장하세요.');
        let url = `https://serpapi.com/search.json?engine=google_scholar&q=${encodeURIComponent(q)}&api_key=${encodeURIComponent(apiKey)}&hl=ko`;
        if (year) url += `&as_ylo=${year}`;
        let res;
        try {
            res = await fetch(url);
        } catch (e) {
            if (e && (e.message === 'Failed to fetch' || e.name === 'TypeError')) {
                try {
                    res = await fetch('https://corsproxy.io/?' + encodeURIComponent(url));
                } catch (e2) {
                    throw new Error('CORS로 차단되었습니다. 로컬 서버(npx serve 등)로 실행하거나 잠시 후 다시 시도하세요.');
                }
            } else throw e;
        }
        if (res.status === 429) throw new Error('SerpAPI 요청 한도 초과(429). 잠시 후 다시 시도하세요.');
        if (!res.ok) throw new Error('Google Scholar 검색 응답 오류');
        const data = await res.json();
        if (data.error) throw new Error(data.error || 'SerpAPI 오류');
        const results = data.organic_results || [];
        return results.map(r => {
            const summary = (r.publication_info && r.publication_info.summary) || '';
            const yearMatch = summary.match(/\b(19|20)\d{2}\b/);
            const _year = yearMatch ? yearMatch[0] : '';
            let doi = '';
            const doiMatch = (r.link || '').match(/doi\.org\/([^\s?#]+)/) || (r.snippet || '').match(/10\.\d{4}\/[^\s]+/);
            if (doiMatch) doi = doiMatch[1] || doiMatch[0];
            const full = `${r.title || ''}. ${summary}. ${r.link || ''}`.trim();
            return {
                _src: 'scholar',
                _title: r.title || '',
                _year,
                _journal: summary,
                _url: r.link || '',
                full,
                DOI: doi,
                author: []
            };
        });
    }

    function renderCards(items) {
        const box = el('ref-results');
        if (!items.length) {
            box.innerHTML = '<div class="cite-empty">검색 결과가 없습니다.<br><span style="font-size:10px">다른 키워드를 시도하거나 Scholar ↗ 버튼으로 Google Scholar를 확인하세요.</span></div>';
            return;
        }
        box.innerHTML = items.map((w, i) => {
            const apa = toAPA(w);
            const doi = w.DOI || w._doi || '';
            const oa = w._oa ? '<span class="ref-tag" style="color:var(--ok);border-color:var(--ok)">OA</span>' : '';
            const src = w._src === 'scholar' ? '<span class="ref-tag">Scholar</span>' : w._src === 'openalex' ? '<span class="ref-tag">OpenAlex</span>' : '<span class="ref-tag">CrossRef</span>';
            const linkBtn = w._url && !(w.DOI || w._doi) ? `<a href="${w._url.replace(/"/g, '&quot;')}" target="_blank" rel="noopener" class="btn btn-g btn-sm">원문 ↗</a>` : '';
            return `<div class="ref-card">
  <div class="ref-card-title">${w._title || '제목 없음'}</div>
  <div class="ref-card-meta">
    ${w._year ? `<b>${w._year}</b> · ` : ''}${w._journal || ''}${w._vol ? ` ${w._vol}` : ''}${w._iss ? `(${w._iss})` : ''}
    ${src}${oa}
  </div>
  <div class="ref-card-apa" id="apa-${i}" title="클릭하면 전체 선택됨">${apa}</div>
  <div class="ref-card-btns">
    <button class="btn btn-p btn-sm" onclick="RefSearch.addToLib(${i})">+ 참고문헌에 추가</button>
    <button class="btn btn-g btn-sm" onclick="RefSearch.copyAPA(${i})">📋 APA 복사</button>
    ${doi ? `<a href="https://doi.org/${doi}" target="_blank" rel="noopener" class="btn btn-g btn-sm">DOI ↗</a>` : ''}
    ${linkBtn}
  </div>
</div>`;
        }).join('');
        box._data = items;
        box._apas = items.map(toAPA);
    }

    async function search() {
        if (_loading) return;
        const db = el('ref-db').value;
        if (db === 'ai') syncAiPromptWithSearch();
        const q = db === 'ai' ? (el('ref-ai-prompt')?.value.trim() || el('ref-q').value.trim()) : el('ref-q').value.trim();
        const year = el('ref-year').value;
        if (!q) {
            if (db === 'ai') el('ref-ai-prompt')?.focus(); else el('ref-q').focus();
            return;
        }

        _loading = true;
        const status = el('ref-status');
        const box = el('ref-results');
        status.textContent = '🔄 검색 중...';
        box.innerHTML = '<div class="cite-empty" style="padding:24px"><div style="font-size:20px;margin-bottom:8px">⏳</div>잠시 기다려 주세요...</div>';

        try {
            let items;
            if (db === 'openalex') {
                items = await searchOpenAlex(q, year);
                status.textContent = `✅ ${items.length}건 검색됨 (OpenAlex) · "${q}"`;
            } else {
                items = await searchCrossRef(q, year);
                status.textContent = `✅ ${items.length}건 검색됨 (CrossRef) · "${q}"`;
            }
            renderCards(items);
        } catch (e) {
            status.textContent = `❌ 오류: ${e.message}`;
            box.innerHTML = `<div class="cite-empty">검색 실패: ${e.message}<br><span style="font-size:10px">네트워크를 확인하거나 Scholar ↗를 사용해주세요.</span></div>`;
        }
        _loading = false;
    }

    function syncAiPromptWithSearch() {
        const qEl = el('ref-q'), pEl = el('ref-ai-prompt');
        if (qEl && pEl) pEl.value = qEl.value;
    }

    function syncAiPromptVisibility() {
        const wrap = document.getElementById('ref-ai-prompt-wrap');
        const dbEl = document.getElementById('ref-db');
        if (wrap && dbEl) {
            const isAi = dbEl.value === 'ai';
            wrap.style.display = isAi ? 'block' : 'none';
            if (isAi) syncAiPromptWithSearch();
        }
    }

    function addToLib(i) {
        const box = el('ref-results');
        const apa = box._apas?.[i];
        if (!apa) return;
        CM.addRaw(apa);
        const btns = box.querySelectorAll('.ref-card')[i]?.querySelectorAll('button');
        if (btns?.[0]) { btns[0].textContent = '✔ 추가됨'; btns[0].disabled = true; btns[0].style.opacity = '.6'; }
    }

    function copyAPA(i) {
        const box = el('ref-results');
        const apa = box._apas?.[i];
        if (!apa) return;
        navigator.clipboard.writeText(apa).then(() => {
            const btns = box.querySelectorAll('.ref-card')[i]?.querySelectorAll('button');
            if (btns?.[1]) { const orig = btns[1].textContent; btns[1].textContent = '✔ 복사됨'; setTimeout(() => btns[1].textContent = orig, 1500); }
        }).catch(() => {
            const el2 = document.createElement('textarea'); el2.value = apa; document.body.appendChild(el2); el2.select(); document.execCommand('copy'); el2.remove();
        });
    }

    function openScholar() {
        const q = el('ref-q').value.trim();
        const url = q ? `https://scholar.google.com/scholar?q=${encodeURIComponent(q)}&hl=ko` : 'https://scholar.google.com/?hl=ko';
        window.open(url, '_blank');
    }

    return { search, addToLib, copyAPA, openScholar, syncAiPromptVisibility, syncAiPromptWithSearch };
})();

(function initRefDbAi() {
    const dbEl = document.getElementById('ref-db');
    const qEl = document.getElementById('ref-q');
    const promptEl = document.getElementById('ref-ai-prompt');
    if (dbEl) dbEl.addEventListener('change', () => RefSearch.syncAiPromptVisibility());
    function syncIfAi() {
        if (dbEl && dbEl.value === 'ai' && qEl && promptEl) {
            qEl.value = promptEl.value;
        }
    }
    function syncFromSearch() {
        if (dbEl && dbEl.value === 'ai' && qEl && promptEl) {
            promptEl.value = qEl.value;
        }
    }
    if (qEl) qEl.addEventListener('input', syncFromSearch);
    if (promptEl) promptEl.addEventListener('input', syncIfAi);
})();
