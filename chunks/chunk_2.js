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

    /* ── 렌더링 ── */
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
        // 데이터 저장 (버튼 콜백용)
        box._data = items;
        box._apas = items.map(toAPA);
    }

    /* ── 검색 실행 ── */
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
        // 버튼 피드백
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
            // fallback
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

    // ref-db 변경 시 AI 프롬프트 영역 표시/숨김 + AI 모드에서 검색어↔프롬프트 동기화
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

/* ═══════════════════════════════════════════════════════════
   COLOR PICKER
═══════════════════════════════════════════════════════════ */
const ColorPicker = (() => {
    let mode = 'text';
    const TEXT_COLORS = ['#e8e8f0', '#ff4444', '#ff8800', '#ffcc00', '#44cc44', '#00aaff', '#aa44ff', '#ff44aa', '#000000', '#333333', '#666666', '#999999', '#cccccc', '#ffffff', '#5b4ce4', '#f7a06a'];
    const BG_COLORS = ['#fff176', '#ffcc80', '#ef9a9a', '#80cbc4', '#a5d6a7', '#90caf9', '#ce93d8', '#f48fb1', '#ffecb3', '#dcedc8', 'transparent'];

    function open(m) {
        mode = m;
        el('color-modal-title').textContent = m === 'text' ? '글자 색상 설정' : '형광펜 하이라이트 색상';
        const colors = m === 'text' ? TEXT_COLORS : BG_COLORS;
        el('color-swatches').innerHTML = colors.map(c => `<div class="csw" style="background:${c === 'transparent' ? 'repeating-linear-gradient(45deg,#888,#888 2px,transparent 2px,transparent 6px)' : c};border-color:${c === '#ffffff' ? '#ccc' : 'transparent'}" onclick="ColorPicker.setHex('${c}')" title="${c}"></div>`).join('');
        el('color-hex').value = '';
        // 스포이드 지원 여부
        const supported = 'EyeDropper' in window;
        el('eyedropper-btn').style.display = supported ? '' : 'none';
        el('eyedrop-support-msg').style.display = supported ? 'none' : 'block';
        // 팔레트 클릭 연동
        el('eyedrop-btn').onclick = e => { e.preventDefault(); el('color-native').click() };
        el('color-modal').classList.add('vis');
        updatePreview('');
    }

    function setHex(c) {
        el('color-hex').value = c;
        // native color input도 동기화 (투명 제외)
        if (c && c !== 'transparent') { try { el('color-native').value = c } catch (e) { } }
        updatePreview(c);
    }

    // <input type="color"> 팔레트에서 선택
    function fromNative(hex) {
        el('color-hex').value = hex;
        updatePreview(hex);
    }

    // EyeDropper API — Chrome 95+ / Edge 95+
    async function eyedrop() {
        if (!('EyeDropper' in window)) {
            el('eyedrop-support-msg').style.display = 'block'; return;
        }
        try {
            // 모달 투명화 → 화면 전체에서 색상 선택 가능
            el('color-modal').style.opacity = '0';
            el('color-modal').style.pointerEvents = 'none';
            const result = await new EyeDropper().open();
            el('color-modal').style.opacity = '';
            el('color-modal').style.pointerEvents = '';
            setHex(result.sRGBHex);
        } catch (e) {
            // 사용자 취소 시 조용히 복원
            el('color-modal').style.opacity = '';
            el('color-modal').style.pointerEvents = '';
        }
    }

    function updatePreview(c) {
        const prev = el('color-preview');
        if (!c || c === 'transparent') { prev.style.color = ''; prev.style.background = ''; return }
        if (mode === 'text') { prev.style.color = c; prev.style.background = '' }
        else { prev.style.background = c; prev.style.color = '' }
    }

    function apply() {
        const c = el('color-hex').value.trim(); if (!c) return;
        const ed = el('editor'); const s = ed.selectionStart, e = ed.selectionEnd; const sel = ed.value.substring(s, e) || '텍스트';
        let wrapped;
        if (mode === 'text') { wrapped = `<span style="color:${c}">${sel}</span>` }
        else { wrapped = c === 'transparent' ? sel : `<span style="background:${c}">${sel}</span>` }
        ins(ed, s, e, wrapped);
        if (mode === 'text') { el('fc-bar').style.background = c }
        else { el('hl-bar').style.background = c }
        App.hideModal('color-modal');
    }

    return { open, setHex, fromNative, eyedrop, updatePreview, apply };
})();

/* ═══════════════════════════════════════════════════════════
   EDITOR ACTIONS
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   IMAGE DROP HANDLER
═══════════════════════════════════════════════════════════ */
const IMG = (() => {
    function dragOver(e) { e.preventDefault(); e.stopPropagation(); el('img-dropzone').style.borderColor = 'var(--ac)'; el('img-dropzone').style.background = 'var(--acg)' }
    function dragLeave(e) { el('img-dropzone').style.borderColor = 'var(--bd)'; el('img-dropzone').style.background = 'var(--bg3)' }
    function drop(e) {
        e.preventDefault(); e.stopPropagation();
        dragLeave(e);
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) loadImage(file);
    }
    function fileSelected(ev) {
        const file = ev.target.files[0];
        if (file) loadImage(file);
        ev.target.value = '';
    }
    function loadImage(file) {
        const reader = new FileReader();
        reader.onload = ev => {
            const dataUrl = ev.target.result;
            el('img-url').value = dataUrl;
            if (!el('img-alt').value) el('img-alt').value = file.name.replace(/\.[^.]+$/, '');
            _showImgpv(dataUrl);
            el('img-drop-text').textContent = '✓ ' + file.name + ' (' + Math.round(file.size / 1024) + 'KB)';
            el('img-drop-text').style.color = 'var(--ok)';
            const cropBtn = document.getElementById('img-insert-crop-btn');
            if (cropBtn) cropBtn.disabled = false;
        };
        reader.readAsDataURL(file);
    }
    return { dragOver, dragLeave, drop, fileSelected };
})();

function _showImgpv(src) {
    const ph = document.getElementById('imgpv-placeholder');
    const img = document.getElementById('imgpv-preview');
    if (!img) return;
    if (src && (src.startsWith('data:image') || src.startsWith('http'))) {
        img.src = src;
        img.style.display = 'block';
        if (ph) ph.style.display = 'none';
    } else {
        img.removeAttribute('src');
        img.style.display = 'none';
        if (ph) ph.style.display = 'block';
    }
}
function _bindImgUrlToImgpv() {
    const urlEl = document.getElementById('img-url');
    if (!urlEl || urlEl._imgpvBound) return;
    urlEl._imgpvBound = true;
    urlEl.addEventListener('input', () => _showImgpv(urlEl.value.trim()));
    urlEl.addEventListener('change', () => _showImgpv(urlEl.value.trim()));
}
function _parseImgCodeToPreview() {
    const ta = document.getElementById('img-code-input');
    if (!ta || !ta.value.trim()) return;
    const html = ta.value.trim();
    const m = html.match(/<img[^>]+src\s*=\s*["']([^"']+)["']/i);
    if (m && m[1]) _showImgpv(m[1]);
}
function _bindImgCodeToPreview() {
    const ta = document.getElementById('img-code-input');
    if (!ta || ta._imgCodeBound) return;
    ta._imgCodeBound = true;
    ta.addEventListener('input', _parseImgCodeToPreview);
    ta.addEventListener('change', _parseImgCodeToPreview);
}

const ImgCrop = {
    openForInsert() {
        const urlEl = document.getElementById('img-url');
        const previewEl = document.getElementById('imgpv-preview');
        const src = (urlEl && urlEl.value && urlEl.value.trim()) || (previewEl && previewEl.src);
        if (!src || (!src.startsWith('data:') && !src.startsWith('http'))) {
            alert('먼저 이미지를 업로드하거나 URL을 입력하세요.');
            return;
        }
        if (src.startsWith('http') && previewEl && !previewEl.complete) {
            alert('이미지 로딩 중입니다. 잠시 후 다시 시도하세요.');
            return;
        }
        window._imgCropTarget = 'insert';
        window._mdliveCropPending = src;
        const w = window.open('crop.html', 'crop', 'width=640,height=560,scrollbars=yes');
        if (!w) { alert('팝업이 차단되었습니다.'); window._imgCropTarget = null; window._mdliveCropPending = null; return; }
    }
};

const ImgInsert = {
    insertToNewFile() {
        const url = document.getElementById('img-url')?.value?.trim();
        const alt = document.getElementById('img-alt')?.value?.trim() || '이미지';
        if (!url) { alert('삽입할 이미지가 없습니다. URL을 입력하거나 이미지를 업로드하세요.'); return; }
        const title = '이미지-' + new Date().toISOString().slice(0, 10);
        if (typeof TM !== 'undefined' && TM.newTab) TM.newTab(title, `![${alt}](${url})`, 'md');
        if (url.startsWith('data:image') && typeof ImgStore !== 'undefined') ImgStore.save(url, alt);
    },
    _codeExamples: [
        '<img src="https://i.ibb.co/vCn4MwWK/pro-render-1771925609150.png" alt="pro render 1771925609150" border="0">',
        '<a href="https://ibb.co/spY9Xm4M"><img src="https://i.ibb.co/2043pnrf/pro-render-1771925609150.png" alt="pro-render-1771925609150" border="0"></a>',
        '<a href="https://ibb.co/spY9Xm4M"><img src="https://i.ibb.co/2043pnrf/pro-render-1771925609150.png" alt="pro-render-1771925609150" border="0"></a>',
        '<a href="https://ibb.co/spY9Xm4M"><img src="https://i.ibb.co/spY9Xm4M/pro-render-1771925609150.png" alt="pro-render-1771925609150" border="0"></a>'
    ],
    setCodeExample(n) {
        const ta = document.getElementById('img-code-input');
        if (ta && this._codeExamples[n - 1]) ta.value = this._codeExamples[n - 1];
        _parseImgCodeToPreview();
    },
    insertHtmlImage() {
        const url = document.getElementById('img-html-url')?.value?.trim();
        const w = document.getElementById('img-html-width')?.value?.trim();
        const h = document.getElementById('img-html-height')?.value?.trim();
        if (!url) { alert('링크를 입력하세요.'); return; }
        let tag = '<img src="' + url.replace(/"/g, '&quot;') + '" alt="" border="0"';
        if (w) tag += ' width="' + w.replace(/"/g, '&quot;') + '"';
        if (h) tag += ' height="' + h.replace(/"/g, '&quot;') + '"';
        tag += '>';
        const ed = document.getElementById('editor');
        if (!ed) return;
        const pos = ed.selectionEnd;
        const v = ed.value;
        ed.value = v.slice(0, pos) + tag + v.slice(pos);
        ed.setSelectionRange(pos + tag.length, pos + tag.length);
        if (typeof App !== 'undefined') App.render();
    }
};

const ImgStore = (() => {
    const DB = 'mdlive-img-store';
    const STORE = 'images';
    function open() {
        return new Promise((res, rej) => {
            const r = indexedDB.open(DB, 1);
            r.onupgradeneeded = e => {
                if (!e.target.result.objectStoreNames.contains(STORE)) e.target.result.createObjectStore(STORE, { keyPath: 'id' });
            };
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
        });
    }
    async function save(dataUrl, alt) {
        if (!dataUrl || !dataUrl.startsWith('data:image')) return;
        const db = await open();
        return new Promise((res, rej) => {
            const t = db.transaction(STORE, 'readwrite');
            t.objectStore(STORE).put({ id: 'img-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9), dataUrl, alt: alt || '', createdAt: Date.now() });
            t.oncomplete = () => res();
            t.onerror = () => rej(t.error);
        });
    }
    return { save };
})();

(function initImgUrlPreview() {
    const urlEl = document.getElementById('img-url');
    if (!urlEl) return;
    urlEl.addEventListener('input', () => {
        const v = urlEl.value.trim();
        const preview = document.getElementById('img-preview');
        const wrap = document.getElementById('img-preview-wrap');
        const cropBtn = document.getElementById('img-insert-crop-btn');
        if (v.startsWith('data:image')) {
            if (preview) { preview.src = v; preview.style.display = 'block'; }
            if (wrap) wrap.style.display = 'block';
            if (cropBtn) cropBtn.disabled = false;
        } else if (cropBtn && (v.startsWith('http') || v.length > 0)) {
            cropBtn.disabled = !v;
        }
    });
})();

/* ═══════════════════════════════════════════════════════════
   AI IMAGE (이미지 모달 내 AI 이미지 탭)
   모델 선택, 시드 이미지, 프롬프트, 생성, 히스토리, 다운로드(일괄/ZIP/프로젝트.mdp), 크롭
═══════════════════════════════════════════════════════════ */
const AiImage = (() => {
    const DB_NAME = 'mdlive-aiimg-history';
    const STORE_NAME = 'history';
    let _seedDataUrl = '';
    let _resultImages = [];
    let _currentPrompt = '';
    let _busy = false;
    let _historyCache = [];
    let _cropImageUrl = '';
    let _cropRect = { x: 0, y: 0, w: 0, h: 0 };
    let _cropDragging = false;
    let _cropStart = { x: 0, y: 0 };
    let _aspectRatio = '1:1';
    let _seedAspectRatio = '';
    let _analysisResult = { face: '', outfit: '' };
    let _analysisHistory = [];
    let _virtualTryOnDataUrl = '';
    let _virtualTryOnExtractedDataUrl = '';

    function _openDB() {
        return new Promise((resolve, reject) => {
            const r = indexedDB.open(DB_NAME, 1);
            r.onerror = () => reject(r.error);
            r.onsuccess = () => resolve(r.result);
            r.onupgradeneeded = (e) => {
                if (!e.target.result.objectStoreNames.contains(STORE_NAME)) {
                    e.target.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
                }
            };
        });
    }
    async function _getAll() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readonly');
            const req = t.objectStore(STORE_NAME).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror = () => reject(req.error);
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
    async function _clearAll() {
        const db = await _openDB();
        return new Promise((resolve, reject) => {
            const t = db.transaction(STORE_NAME, 'readwrite');
            t.objectStore(STORE_NAME).clear();
            t.oncomplete = () => resolve();
            t.onerror = () => reject(t.error);
        });
    }

    function switchTab(tab) {
        const insertPanel = el('img-insert-panel');
        const historyPanel = el('aiimg-history-panel');
        const centerInsert = el('imgpv');
        const centerAi = el('img-center-ai');
        const rightSidebar = el('img-right-sidebar');
        const box = el('image-modal-box');
        const tabs = document.querySelectorAll('.img-side-tab');
        if (!insertPanel || !historyPanel) return;
        if (tab === 'ai') {
            insertPanel.style.display = 'none';
            historyPanel.style.display = 'flex';
            if (centerInsert) centerInsert.style.display = 'none';
            if (centerAi) centerAi.style.display = 'flex';
            if (rightSidebar) { rightSidebar.style.display = 'flex'; }
            if (box) box.style.maxWidth = '960px';
            tabs.forEach(t => { t.classList.toggle('active', t.getAttribute('data-tab') === 'ai'); });
            loadHistory();
        } else {
            insertPanel.style.display = 'block';
            historyPanel.style.display = 'none';
            if (centerInsert) centerInsert.style.display = 'flex';
            if (centerAi) centerAi.style.display = 'none';
            if (rightSidebar) rightSidebar.style.display = 'none';
            if (box) box.style.maxWidth = '720px';
            tabs.forEach(t => { t.classList.toggle('active', t.getAttribute('data-tab') === 'insert'); });
        }
    }

    function toggleMaximize() {
        const box = el('image-modal-box');
        if (!box) return;
        const on = box.classList.toggle('img-modal-maximized');
        if (on) {
            box.style.maxWidth = '';
        } else {
            const isAi = document.querySelector('.img-side-tab.active')?.getAttribute('data-tab') === 'ai';
            box.style.maxWidth = isAi ? '960px' : '720px';
        }
        const btn = document.getElementById('img-modal-maximize');
        if (btn) {
            btn.textContent = on ? '전체화면 해제' : '전체화면';
            btn.title = on ? '전체화면 해제' : '전체화면';
        }
    }

    function _gcd(a, b) { return b ? _gcd(b, a % b) : a; }
    function _setSeedAspectRatio(dataUrl) {
        _seedAspectRatio = '';
        if (!dataUrl) return;
        const img = new Image();
        img.onload = function() {
            const w = img.naturalWidth, h = img.naturalHeight;
            if (w && h) {
                const g = _gcd(w, h);
                _seedAspectRatio = (w / g) + ':' + (h / g);
            }
        };
        img.src = dataUrl;
    }
    (function initRatioButtons() {
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.aiimg-ratio');
            if (!btn) return;
            const sidebar = document.getElementById('img-right-sidebar');
            if (!sidebar || sidebar.style.display === 'none') return;
            document.querySelectorAll('.aiimg-ratio').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            _aspectRatio = btn.getAttribute('data-ratio') || '1:1';
            const ta = document.getElementById('aiimg-prompt');
            if (ta) {
                const v = ta.value || '';
                ta.value = v.replace(/\s*\[비율:\s*[\d:]+\]\s*/g, '').replace(/\s*[\d:]+\s*비율로\s*(해줘|넣어줘)\s*/g, '').trim();
                const ratioText = _aspectRatio + ' 비율로 넣어줘';
                const suffix = ' ' + ratioText;
                if (ta.value) ta.value = ta.value + suffix;
                else ta.value = ratioText;
            }
        });
    })();

    const PRESETS = {
        person: 'Same person. Keep the same character. ',
        outfit: 'Same outfit. Keep the same clothing. ',
        diagram: 'Flowchart, statistics diagram. Clear and readable. ',
        chart: 'Chart visualization. ',
        story: 'Notebook LM style story illustration. '
    };
    const MENU_TYPE_EN = {
        '극사실주의': 'hyperrealism',
        '스튜디오': 'studio',
        '패션': 'fashion',
        '일본만화': 'japanese manga style',
        '수채화': 'watercolor',
        '단순화그림체': 'simplified illustration style'
    };
    function applyPreset(type) {
        const ta = el('aiimg-prompt');
        if (!ta) return;
        let prefix = '';
        if (type === 'person') {
            const faceText = _analysisResult.face || (document.getElementById('aiimg-analysis-text') && document.getElementById('aiimg-analysis-text').textContent.trim()) || '';
            if (faceText) {
                prefix = faceText + '\n\nKeep the same person. Maintain the character\'s face and appearance. ';
            } else {
                prefix = PRESETS.person;
            }
        } else if (type === 'outfit') {
            if (_analysisResult.outfit) prefix = '[복장 고정]\n' + _analysisResult.outfit + '\n\n';
            else prefix = PRESETS.outfit;
        } else {
            prefix = PRESETS[type] || '';
        }
        ta.value = prefix + (ta.value || '');
        ta.focus();
    }
    function sendAnalysisToPrompt() {
        const analysisEl = document.getElementById('aiimg-analysis-text');
        const ta = document.getElementById('aiimg-prompt');
        if (!analysisEl || !ta) return;
        const text = (analysisEl.textContent || '').trim();
        if (!text) return;
        const current = (ta.value || '').trim();
        ta.value = current ? current + '\n\n' + text : text;
        ta.focus();
    }
    function applyMenuType(type) {
        const ta = el('aiimg-prompt');
        if (!ta) return;
        const en = MENU_TYPE_EN[type] || type;
        const text = (ta.value || '').trim();
        ta.value = text ? text + ', ' + en : en;
        ta.focus();
    }
    async function analyzeSeedImage() {
        if (!_seedDataUrl) return;
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) { alert('AI API 키를 설정에서 입력해 주세요.'); return; }
        const btn = document.getElementById('aiimg-analyze-btn');
        if (btn) btn.disabled = true;
        const analysisEl = document.getElementById('aiimg-analysis-text');
        if (analysisEl) analysisEl.textContent = '분석 중…';
        try {
            const base64 = _seedDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const mime = _seedDataUrl.match(/^data:(image\/\w+);/);
            const modelId = 'gemini-2.5-flash';
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
            const body = {
                contents: [{
                    role: 'user',
                    parts: [
                        { inlineData: { mimeType: mime ? mime[1] : 'image/png', data: base64 } },
                        { text: '이 이미지에 등장하는 인물과 복장을 분석해서 다음 형식으로만 답해. 다른 말 없이 아래 형식만.\n\n[인물]\n얼굴: 눈 특징, 눈썹, 코, 입 모양, 피부톤 등\n헤어: 길이, 스타일, 색 등\n기타: 성별, 나이대 등\n\n[복장]\n상의, 하의, 악세서리 등 입은 옷과 스타일을 구체적으로.' }
                    ]
                }],
                generationConfig: { temperature: 0.2, maxOutputTokens: 1024 }
            };
            const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
            const data = await r.json();
            if (!r.ok) throw new Error(data.error?.message || 'API 오류');
            const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
            const faceMatch = text.match(/\[인물\]([\s\S]*?)(?=\[복장\]|$)/);
            const outfitMatch = text.match(/\[복장\]([\s\S]*?)$/);
            _analysisResult.face = faceMatch ? faceMatch[1].trim() : '';
            _analysisResult.outfit = outfitMatch ? outfitMatch[1].trim() : '';
            const displayText = (_analysisResult.face ? '[인물]\n' + _analysisResult.face + '\n\n' : '') + (_analysisResult.outfit ? '[복장]\n' + _analysisResult.outfit : '') || '분석 결과 없음';
            if (analysisEl) analysisEl.textContent = displayText;
            _analysisHistory.unshift({
                id: 'analysis-' + Date.now(),
                text: displayText,
                face: _analysisResult.face,
                outfit: _analysisResult.outfit,
                createdAt: Date.now()
            });
            if (_analysisHistory.length > 50) _analysisHistory.pop();
        } catch (e) {
            if (analysisEl) analysisEl.textContent = '오류: ' + (e.message || String(e));
        }
        if (btn) btn.disabled = false;
    }
    function onVirtualTryOnFile(ev) {
        const file = ev.target.files[0];
        if (!file || !file.type.startsWith('image/')) return;
        ev.target.value = '';
        const reader = new FileReader();
        reader.onload = () => {
            _virtualTryOnDataUrl = reader.result;
            _virtualTryOnExtractedDataUrl = '';
            const imgEl = document.getElementById('aiimg-virtual-tryon-img');
            const wrap = document.getElementById('aiimg-virtual-tryon-preview');
            const nameEl = document.getElementById('aiimg-virtual-tryon-name');
            const clearBtn = document.getElementById('aiimg-virtual-tryon-clear');
            const extractedWrap = document.getElementById('aiimg-virtual-tryon-extracted-wrap');
            const extractedImg = document.getElementById('aiimg-virtual-tryon-extracted-img');
            const extractedLoading = document.getElementById('aiimg-virtual-tryon-extracted-loading');
            if (imgEl) imgEl.src = _virtualTryOnDataUrl;
            if (wrap) wrap.style.display = 'block';
            const descEl = document.getElementById('aiimg-virtual-tryon-desc');
            if (descEl) descEl.textContent = '옷 이미지 또는 인물 이미지를 올리면 AI가 옷을 추출하고, 생성 시 적용됩니다.';
            if (nameEl) nameEl.textContent = file.name;
            if (clearBtn) clearBtn.disabled = false;
            const reextractBtn = document.getElementById('aiimg-virtual-tryon-reextract');
            if (reextractBtn) reextractBtn.disabled = false;
            const refExtracted = document.getElementById('aiimg-tryon-ref-extracted');
            if (refExtracted) refExtracted.checked = true;
            if (extractedWrap) { extractedWrap.style.display = 'none'; if (extractedImg) extractedImg.style.display = 'none'; }
            extractClothingForTryOn();
        };
        reader.readAsDataURL(file);
    }
    async function extractClothingForTryOn() {
        if (!_virtualTryOnDataUrl) return;
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) return;
        const modelId = (el('aiimg-model') && el('aiimg-model').value) || 'gemini-2.0-flash-exp-image-generation';
        const extractedWrap = document.getElementById('aiimg-virtual-tryon-extracted-wrap');
        const extractedImg = document.getElementById('aiimg-virtual-tryon-extracted-img');
        const extractedLoading = document.getElementById('aiimg-virtual-tryon-extracted-loading');
        if (extractedLoading) { extractedLoading.style.display = 'block'; extractedImg.style.display = 'none'; }
        if (extractedWrap) extractedWrap.style.display = 'block';
        try {
            const base64 = _virtualTryOnDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const mime = _virtualTryOnDataUrl.match(/^data:(image\/\w+);/);
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
            const body = {
                contents: [{
                    role: 'user',
                    parts: [
                        { inlineData: { mimeType: mime ? mime[1] : 'image/png', data: base64 } },
                        { text: '이 이미지에서 옷(의상)만 추출해서 흰색 배경 위에 의상만 보이게 해줘. 인물은 제거하고 옷만 보이게 생성해 줘.' }
                    ]
                }],
                generationConfig: {
                    responseModalities: ['TEXT', 'IMAGE'],
                    responseMimeType: 'text/plain'
                }
            };
            const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
            const data = await r.json();
            if (!r.ok) throw new Error(data.error?.message || 'API 오류');
            const parts = data.candidates?.[0]?.content?.parts || [];
            let extractedDataUrl = '';
            parts.forEach(p => {
                if (p.inlineData && p.inlineData.data) {
                    const mt = p.inlineData.mimeType || 'image/png';
                    extractedDataUrl = 'data:' + mt + ';base64,' + p.inlineData.data;
                }
            });
            if (extractedDataUrl) {
                _virtualTryOnExtractedDataUrl = extractedDataUrl;
                if (extractedImg) { extractedImg.src = extractedDataUrl; extractedImg.style.display = 'block'; }
            }
        } catch (e) {
            if (extractedLoading) {
                extractedLoading.textContent = '오류: ' + (e.message || String(e)).slice(0, 40);
                extractedLoading.style.display = 'block';
            }
        }
        if (extractedLoading && _virtualTryOnExtractedDataUrl) extractedLoading.style.display = 'none';
    }
    function clearVirtualTryOn() {
        _virtualTryOnDataUrl = '';
        _virtualTryOnExtractedDataUrl = '';
        const imgEl = document.getElementById('aiimg-virtual-tryon-img');
        const wrap = document.getElementById('aiimg-virtual-tryon-preview');
        const nameEl = document.getElementById('aiimg-virtual-tryon-name');
        const clearBtn = document.getElementById('aiimg-virtual-tryon-clear');
        const input = document.getElementById('aiimg-virtual-tryon-input');
        const extractedWrap = document.getElementById('aiimg-virtual-tryon-extracted-wrap');
        const extractedImg = document.getElementById('aiimg-virtual-tryon-extracted-img');
        const extractedLoading = document.getElementById('aiimg-virtual-tryon-extracted-loading');
        if (imgEl) imgEl.src = '';
        if (wrap) wrap.style.display = 'none';
        const descEl = document.getElementById('aiimg-virtual-tryon-desc');
        if (descEl) descEl.textContent = '이미지가 없는 경우 참고하지 않습니다.';
        if (nameEl) nameEl.textContent = '';
        if (clearBtn) clearBtn.disabled = true;
        if (input) input.value = '';
        const reextractBtn = document.getElementById('aiimg-virtual-tryon-reextract');
        if (reextractBtn) reextractBtn.disabled = true;
        if (extractedWrap) extractedWrap.style.display = 'none';
        if (extractedImg) extractedImg.src = '';
        if (extractedLoading) { extractedLoading.style.display = 'none'; extractedLoading.textContent = '추출 중…'; }
    }

    function onSeedFile(ev) {
        const file = ev.target.files[0];
        if (!file || !file.type.startsWith('image/')) return;
        const reader = new FileReader();
        reader.onload = () => {
            _seedDataUrl = reader.result;
            _setSeedAspectRatio(_seedDataUrl);
            const preview = el('aiimg-seed-preview');
            const placeholder = el('aiimg-seed-placeholder');
            if (preview) { preview.src = _seedDataUrl; preview.style.display = 'block'; }
            if (placeholder) placeholder.style.display = 'none';
            const bigBtn = document.getElementById('aiimg-seed-big-btn');
            if (bigBtn) bigBtn.style.display = 'block';
            el('aiimg-crop-btn').disabled = false;
        };
        reader.readAsDataURL(file);
        ev.target.value = '';
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
    function clearSeed() {
        _seedDataUrl = '';
        _seedAspectRatio = '';
        _analysisResult = { face: '', outfit: '' };
        const preview = el('aiimg-seed-preview');
        const placeholder = el('aiimg-seed-placeholder');
        if (preview) { preview.src = ''; preview.style.display = 'none'; }
        if (placeholder) placeholder.style.display = 'block';
        const bigBtn = document.getElementById('aiimg-seed-big-btn');
        if (bigBtn) bigBtn.style.display = 'none';
        el('aiimg-crop-btn').disabled = true;
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = true;
        const analysisEl = document.getElementById('aiimg-analysis-text');
        if (analysisEl) analysisEl.textContent = '';
        const personCb = document.getElementById('aiimg-fix-person-cb');
        const outfitCb = document.getElementById('aiimg-fix-outfit-cb');
        if (personCb) personCb.checked = false;
        if (outfitCb) outfitCb.checked = false;
    }
    function setResultAsSeed() {
        if (_resultImages.length === 0) return;
        if (_virtualTryOnExtractedDataUrl && _resultImages[0] === _virtualTryOnExtractedDataUrl) {
            alert('Try-on 추출 이미지는 시드로 사용할 수 없습니다.');
            return;
        }
        _seedDataUrl = _resultImages[0];
        if (_virtualTryOnExtractedDataUrl && _seedDataUrl === _virtualTryOnExtractedDataUrl) return;
        _setSeedAspectRatio(_seedDataUrl);
        const preview = el('aiimg-seed-preview');
        const placeholder = el('aiimg-seed-placeholder');
        if (preview) { preview.src = _seedDataUrl; preview.style.display = 'block'; }
        if (placeholder) placeholder.style.display = 'none';
        const bigBtn = document.getElementById('aiimg-seed-big-btn');
        if (bigBtn) bigBtn.style.display = 'block';
        el('aiimg-crop-btn').disabled = false;
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = false;
    }

    function openCropUpload() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*';
        input.onchange = (ev) => {
            const file = ev.target.files[0];
            if (!file || !file.type.startsWith('image/')) return;
            const reader = new FileReader();
            reader.onload = () => _openCropPopup(reader.result);
            reader.readAsDataURL(file);
        };
        input.click();
    }
    function openCropEdit() {
        if (!_seedDataUrl) return;
        _openCropPopup(_seedDataUrl);
    }
    function openTryOnCropEdit() {
        if (!_virtualTryOnDataUrl) return;
        window._imgCropTarget = 'tryon';
        _openCropPopup(_virtualTryOnDataUrl);
    }
    function openTryOnExtractedCropEdit() {
        if (!_virtualTryOnExtractedDataUrl) return;
        window._imgCropTarget = 'tryon-extracted';
        _openCropPopup(_virtualTryOnExtractedDataUrl);
    }
    function openCropForResult(index) {
        const dataUrl = _resultImages[index];
        if (!dataUrl) return;
        window._imgCropTarget = 'result';
        window._cropResultIndex = index;
        _openCropPopup(dataUrl);
    }
    function openResultInNewWindow(dataUrl) {
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes');
        if (!w) return;
        const esc = (s) => (s || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
        const html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>이미지 보기</title><style>body{margin:0;background:#1a1a2e;display:flex;flex-direction:column;min-height:100vh;align-items:center}.img-toolbar{flex-shrink:0;padding:8px;display:flex;gap:8px;align-items:center}.img-toolbar button{padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px;border:1px solid #4a4a6a;background:#2a2a3a;color:#e8e8f0}.img-toolbar button:hover{background:#3a3a4a}.img-wrap{flex:1;overflow:auto;display:flex;align-items:flex-start;justify-content:center;padding:12px;min-height:0}.img-wrap img{display:block}</style></head><body><div class="img-toolbar"><button type="button" id="zoomOut">축소</button><button type="button" id="zoomIn">확대</button><span id="zoomPct" style="color:#888;font-size:13px;min-width:60px">100%</span></div><div class="img-wrap" id="imgWrap"><img id="viewImg" src="' + esc(dataUrl) + '" alt=""></div><script>(function(){var img=document.getElementById("viewImg");var wrap=document.getElementById("imgWrap");var pct=document.getElementById("zoomPct");var scale=1;var nw,nh;function update(){if(nw&&nh){img.style.width=(nw*scale)+"px";img.style.height=(nh*scale)+"px";wrap.style.width=(nw*scale)+"px";wrap.style.height=(nh*scale)+"px";}pct.textContent=Math.round(scale*100)+"%";}img.onload=function(){nw=img.naturalWidth;nh=img.naturalHeight;update();};document.getElementById("zoomIn").onclick=function(){scale=Math.min(scale*1.25,5);update();};document.getElementById("zoomOut").onclick=function(){scale=Math.max(scale/1.25,0.2);update();};})();</script></body></html>';
        w.document.write(html);
        w.document.close();
    }
    function openSeedInNewWindow() {
        if (!_seedDataUrl) return;
        openResultInNewWindow(_seedDataUrl);
    }
    function openTryOnImageInNewWindow(type) {
        const imgEl = type === 'extracted' ? document.getElementById('aiimg-virtual-tryon-extracted-img') : document.querySelector('#aiimg-virtual-tryon-img');
        const src = imgEl && imgEl.src;
        if (!src || src === window.location.href) return;
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes');
        if (!w) return;
        w.document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>이미지 보기</title><style>body{margin:0;background:#1a1a2e;display:flex;align-items:center;justify-content:center;min-height:100vh}</style></head><body><img src="' + src.replace(/"/g, '&quot;') + '" style="max-width:100%;max-height:100vh;object-fit:contain" alt=""></body></html>');
        w.document.close();
    }
    function cropCurrentResult() {
        if (_resultImages.length === 0) return;
        openCropForResult(0);
    }
    function openCurrentResultInNewWindow() {
        if (_resultImages.length === 0) return;
        openResultInNewWindow(_resultImages[0]);
    }
    function resetModal() {
        _seedDataUrl = '';
        _seedAspectRatio = '';
        _resultImages = [];
        _currentPrompt = '';
        _analysisResult = { face: '', outfit: '' };
        _virtualTryOnDataUrl = '';
        const preview = el('aiimg-seed-preview');
        const placeholder = el('aiimg-seed-placeholder');
        if (preview) { preview.src = ''; preview.style.display = 'none'; }
        if (placeholder) placeholder.style.display = 'block';
        const seedBigBtn = document.getElementById('aiimg-seed-big-btn');
        if (seedBigBtn) seedBigBtn.style.display = 'none';
        const cropBtn = document.getElementById('aiimg-crop-btn');
        if (cropBtn) cropBtn.disabled = true;
        if (el('aiimg-prompt')) el('aiimg-prompt').value = '';
        const centerCrop = document.getElementById('aiimg-center-crop-btn');
        const centerBig = document.getElementById('aiimg-center-big-btn');
        if (centerCrop) centerCrop.disabled = true;
        if (centerBig) centerBig.disabled = true;
        const rw = el('aiimg-result-wrap');
        const empty = el('aiimg-empty-result');
        if (rw) rw.style.display = 'none';
        if (empty) empty.style.display = 'flex';
        const wrap = el('aiimg-result-images');
        if (wrap) wrap.innerHTML = '';
        const analyzeBtn = document.getElementById('aiimg-analyze-btn');
        if (analyzeBtn) analyzeBtn.disabled = true;
        const analysisEl = document.getElementById('aiimg-analysis-text');
        if (analysisEl) analysisEl.textContent = '';
        const personCb = document.getElementById('aiimg-fix-person-cb');
        const outfitCb = document.getElementById('aiimg-fix-outfit-cb');
        if (personCb) personCb.checked = false;
        if (outfitCb) outfitCb.checked = false;
        clearVirtualTryOn();
    }
    function _openCropPopup(imageDataUrl) {
        const w = window.open('crop.html', 'crop', 'width=640,height=560,scrollbars=yes');
        if (!w) { alert('팝업이 차단되었습니다. 크롭 창을 허용해 주세요.'); return; }
        window._mdliveCropPending = imageDataUrl;
    }
    (function initCropMessage() {
        window.addEventListener('message', (ev) => {
            if (ev.data && ev.data.type === 'crop-ready') {
                const img = window._mdliveCropPending;
                window._mdliveCropPending = null;
                if (ev.source && !ev.source.closed && img) ev.source.postMessage({ type: 'crop', image: img }, '*');
                return;
            }
            if (!ev.data || ev.data.type !== 'aiimg-cropped' || !ev.data.dataUrl) return;
            if (window._imgCropTarget === 'tryon') {
                window._imgCropTarget = null;
                _virtualTryOnDataUrl = ev.data.dataUrl;
                const imgEl = document.getElementById('aiimg-virtual-tryon-img');
                if (imgEl) { imgEl.src = _virtualTryOnDataUrl; }
                return;
            }
            if (window._imgCropTarget === 'tryon-extracted') {
                window._imgCropTarget = null;
                _virtualTryOnExtractedDataUrl = ev.data.dataUrl;
                const imgEl = document.getElementById('aiimg-virtual-tryon-extracted-img');
                if (imgEl) { imgEl.src = _virtualTryOnExtractedDataUrl; imgEl.style.display = 'block'; }
                const loadingEl = document.getElementById('aiimg-virtual-tryon-extracted-loading');
                if (loadingEl) loadingEl.style.display = 'none';
                return;
            }
            if (window._imgCropTarget === 'result' && typeof window._cropResultIndex === 'number') {
                const idx = window._cropResultIndex;
                window._imgCropTarget = null;
                window._cropResultIndex = null;
                if (_resultImages[idx] !== undefined) {
                    _resultImages[idx] = ev.data.dataUrl;
                    _renderResult();
                }
                return;
            }
            if (window._imgCropTarget === 'insert') {
                window._imgCropTarget = null;
                const urlEl = el('img-url');
                if (urlEl) urlEl.value = ev.data.dataUrl;
                _showImgpv(ev.data.dataUrl);
                return;
            }
            if (_virtualTryOnExtractedDataUrl && ev.data.dataUrl === _virtualTryOnExtractedDataUrl) {
                alert('Try-on 추출 이미지는 시드로 사용할 수 없습니다.');
                return;
            }
            _seedDataUrl = ev.data.dataUrl;
            _setSeedAspectRatio(_seedDataUrl);
            const preview = el('aiimg-seed-preview');
            const placeholder = el('aiimg-seed-placeholder');
            if (preview) { preview.src = _seedDataUrl; preview.style.display = 'block'; }
            if (placeholder) placeholder.style.display = 'none';
            const bigBtn = document.getElementById('aiimg-seed-big-btn');
            if (bigBtn) bigBtn.style.display = 'block';
            const cropBtn = document.getElementById('aiimg-crop-btn');
            if (cropBtn) cropBtn.disabled = false;
            const analyzeBtn = document.getElementById('aiimg-analyze-btn');
            if (analyzeBtn) analyzeBtn.disabled = false;
        });
    })();
