/* Translator - 번역기 (Shift+Alt+G) -> js/ai/translator.js. 의존: el, AiApiKey, US, TM, App, AppLock */


/* ═══════════════════════════════════════════════════════════
   TRANSLATOR — 번역기 (Shift+Alt+G)
   1순위: MyMemory API (무료·CORS OK·API키 불필요)
   2순위: 공개 LibreTranslate 인스턴스
═══════════════════════════════════════════════════════════ */
const Translator = (() => {
    let _lastResult = '';
    let _busy = false;
    let _currentTab = 'translate';

    /* ── Gemini API 호출 ─────────────────────────────────── */
    const _LANG_NAMES = { ko:'한국어', en:'영어', ja:'일본어', zh:'중국어', fr:'프랑스어', de:'독일어', es:'스페인어', ru:'러시아어', pt:'포르투갈어', it:'이탈리아어', ar:'아랍어' };
    async function _callGemini(prompt, userText, modelId) {
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) throw new Error('AI API 키를 설정에서 입력·저장해 주세요.');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
        const body = {
            contents: [{ parts: [{ text: prompt + '\n\n' + userText }] }],
            generationConfig: { temperature: 0.4, maxOutputTokens: 8192 }
        };
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(60000)
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error?.message || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const txt = d.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!txt) throw new Error('AI 응답이 비어 있습니다.');
        return txt.trim();
    }

    /* ── MyMemory (1순위) ───────────────────────────────── */
    const _MM_CODE = { zh:'zh-CN', ko:'ko', en:'en', ja:'ja',
                       fr:'fr',   de:'de', es:'es', ru:'ru',
                       pt:'pt',   it:'it', ar:'ar' };

    async function _myMemory(text, sl, tl) {
        const sc = _MM_CODE[sl] || sl;
        const tc = _MM_CODE[tl] || tl;
        const url = `https://api.mymemory.translated.net/get` +
                    `?q=${encodeURIComponent(text)}&langpair=${sc}|${tc}`;
        const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        if (d.responseStatus !== 200)
            throw new Error(d.responseDetails || d.responseStatus || 'MyMemory 오류');
        const t = d.responseData?.translatedText;
        /* MyMemory가 그대로 반환하거나 에러문 반환 시 예외 */
        if (!t || (typeof t === 'string' && t === text)) throw new Error('번역 결과 없음');
        return String(t);
    }

    /* ── LibreTranslate 공개 인스턴스 (2순위, #tr-translate-btn 시 사용) ─────────────── */
    const _LT_HOSTS = [
        'https://de.libretranslate.com',
        'https://libretranslate.de',
        'https://translate.cutie.dating',
    ];
    async function _libreTranslate(text, sl, tl) {
        for (const host of _LT_HOSTS) {
            try {
                const r = await fetch(`${host}/translate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ q: text, source: sl, target: tl, format: 'text' }),
                    signal: AbortSignal.timeout(12000),
                });
                if (!r.ok) continue;
                const d = await r.json();
                const t = d.translatedText || d.translation;
                if (t) return t;
            } catch { /* 다음 서버 시도 */ }
        }
        throw new Error('모든 번역 서버에 접속할 수 없습니다');
    }

    /* ── 구글 번역 모바일 스크래핑 (R 방식: URL 요청 후 .result-container 파싱) ───────────── */
    async function _googleTranslateScrape(text, sl, tl) {
        const url = 'https://translate.google.com/m?sl=' + encodeURIComponent(sl) +
            '&hl=' + encodeURIComponent(tl) +
            '&q=' + encodeURIComponent(text);
        const proxyUrl = 'https://corsproxy.io/?' + encodeURIComponent(url);
        const r = await fetch(proxyUrl, {
            signal: AbortSignal.timeout(15000),
            headers: { 'Accept': 'text/html' }
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const html = await r.text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const selectors = ['.result-container', '.result-div', '.translated-ltr', '[data-result-index]'];
        let result = '';
        for (const sel of selectors) {
            const el = doc.querySelector(sel);
            if (el && (el.textContent || '').trim()) {
                result = el.textContent.trim();
                break;
            }
        }
        if (!result) throw new Error('구글 번역 결과를 찾을 수 없습니다');
        return result;
    }

    async function _doTranslate(text, sl, tl) {
        const engineEl = document.getElementById('tr-engine');
        const engine = (engineEl && engineEl.value) || 'google';
        if (engine === 'google') {
            return await _googleTranslateScrape(text, sl, tl);
        }
        if (engine === 'mymemory') {
            return await _myMemory(text, sl, tl);
        }
        if (engine === 'libre') {
            return await _libreTranslate(text, sl, tl);
        }
        return await _googleTranslateScrape(text, sl, tl);
    }

    /* ── UI 유틸 ──────────────────────────────────────── */
    const $ = id => document.getElementById(id);
    function _setStatus(msg, type) {
        const el = $('tr-status');
        if (!el) return;
        el.textContent = msg;
        el.style.color = type === 'ok'   ? 'var(--ok)'  :
                         type === 'err'  ? 'var(--er)'  :
                         type === 'warn' ? '#f7c060'    : 'var(--tx3)';
    }
    function _updateCount() {
        const inp = $('tr-input'), cnt = $('tr-input-count');
        if (inp && cnt) cnt.textContent = inp.value.length + '자';
    }

    /* ── 공개 API ─────────────────────────────────────── */
    function show(initialText) {
        const modal = $('translator-modal');
        if (!modal) return;
        const inp = $('tr-input');
        if (inp) {
            if (initialText != null && initialText !== '') {
                inp.value = typeof initialText === 'string' ? initialText : String(initialText);
                _updateCount();
            } else {
                const ed = $('editor');
                if (ed) {
                    const sel = ed.value.substring(ed.selectionStart, ed.selectionEnd).trim();
                    if (sel) { inp.value = sel; _updateCount(); }
                }
            }
        }
        modal.classList.add('vis');
        switchTab('translate');
        setTimeout(() => { const i = $('tr-input'); if (i) i.focus(); }, 60);
    }

    function openOriginalAndTranslationInNewWindow() {
        const inp = $('tr-input'), out = $('tr-output');
        const orig = inp ? inp.value.trim() : '';
        const trans = out ? out.value.trim() : '';
        if (!orig && !trans) {
            alert('원문 또는 번역 결과가 없습니다.');
            return;
        }
        const combined = trans ? (orig + '\n\n--- 번역 ---\n' + trans) : orig;
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>원문 + 번역</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3)">' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-combined-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-combined-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">축소</button>' +
            '<span id="tr-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '</div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre id="tr-combined-content" style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        var el = w.document.getElementById('tr-combined-content');
        if (el) el.textContent = combined;
    }

    /** 번역 결과(tr-output)만 클립보드에 복사하고 새 창으로 띄움. 구글번역 등에서 붙여넣은 결과에 유용. */
    function openTranslationInNewWindow() {
        const out = $('tr-output');
        const txt = out ? out.value.trim() : _lastResult || '';
        if (!txt) {
            alert('번역 결과가 없습니다. 구글번역 등에서 번역한 뒤 여기에 붙여넣고 다시 시도하세요.');
            return;
        }
        navigator.clipboard.writeText(txt).catch(() => {});
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>번역 결과</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3)">' +
            '<span style="font-size:11px;color:var(--tx3)">번역 결과 (클립보드에 복사됨)</span>' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-only-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'tr-only-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'tr-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx)">축소</button>' +
            '<span id="tr-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '</div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre id="tr-only-content" style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        const el = w.document.getElementById('tr-only-content');
        if (el) el.textContent = txt;
        _setStatus('번역 결과를 복사했고 새 창을 열었습니다.', 'ok');
        setTimeout(() => _setStatus(''), 3000);
    }

    /** (en/ko 간단용) 구글 스크래핑으로 번역만 수행. 외부(DR 생각 등)에서 호출. */
    function translateText(text, sl, tl) {
        return _googleTranslateScrape(text, sl || 'en', tl || 'ko');
    }

    /** (en/ko 간단용) 텍스트만으로 구글 번역 탭 열기. 번역기 모달 구글번역기 버튼과 동일한 데스크톱 URL 사용. */
    function openBrowserWithText(text, sl, tl) {
        const s = sl || 'en', t = tl || 'ko';
        window.open(
            'https://translate.google.com/?sl=' + encodeURIComponent(s) + '&tl=' + encodeURIComponent(t) + '&text=' + encodeURIComponent(text) + '&op=translate',
            '_blank'
        );
    }

    /** (en/ko 간단용) 번역문만 새 창으로 띄움. */
    function openTranslationInNewWindowWithText(txt) {
        if (!txt) return;
        navigator.clipboard.writeText(txt).catch(() => {});
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>번역 결과</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3)">' +
            '<span style="font-size:11px;color:var(--tx3)">번역 결과 (클립보드에 복사됨)</span>' +
            '</div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        const pre = w.document.querySelector('pre');
        if (pre) pre.textContent = txt;
    }

    /** (en/ko 간단용) 원문+번역 새 창으로 띄움. */
    function openOriginalAndTranslationInNewWindowWithText(orig, trans) {
        const combined = (orig || '') + (trans ? '\n\n--- 번역 ---\n' + trans : '');
        if (!combined.trim()) return;
        const w = window.open('', '_blank', 'width=800,height=600,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>원문 + 번역</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);background:var(--bg3)"></div>' +
            '<div style="flex:1;min-height:0;overflow:auto;padding:20px">' +
            '<pre style="white-space:pre-wrap;word-break:break-word;max-width:720px;margin:0 auto;font-size:13px;line-height:1.7;font-family:inherit"></pre>' +
            '</div></body></html>'
        );
        w.document.close();
        const pre = w.document.querySelector('pre');
        if (pre) pre.textContent = combined;
    }

    function hide() {
        const m = $('translator-modal');
        if (m) m.classList.remove('vis');
        const inner = document.getElementById('translator-modal-inner');
        if (inner) inner.classList.remove('tr-maximized');
    }

    function toggleFullscreen() {
        const el = document.getElementById('translator-modal-inner');
        if (!el) return;
        const on = el.classList.toggle('tr-maximized');
        const btn = document.getElementById('tr-fullscreen-btn');
        if (btn) {
            btn.textContent = on ? '전체화면 해제' : '전체화면';
            btn.title = on ? '전체화면 해제' : '전체화면';
        }
    }

    function switchTab(tab) {
        _currentTab = tab;
        document.querySelectorAll('#tr-tabs .tr-tab').forEach(b => {
            b.classList.toggle('active', b.dataset.tab === tab);
        });
        const aiTrans = $('tr-ai-translate-panel'), aiWrite = $('tr-ai-write-panel'), langRow = $('tr-lang-row'), engineRow = $('tr-engine-row'), transBtn = $('tr-translate-btn');
        if (aiTrans) aiTrans.style.display = (tab === 'ai-translate') ? 'flex' : 'none';
        if (aiWrite) aiWrite.style.display = (tab === 'ai-write') ? 'flex' : 'none';
        if (langRow) langRow.style.display = (tab === 'translate' || tab === 'ai-translate') ? 'flex' : 'none';
        if (engineRow) engineRow.style.display = (tab === 'translate') ? 'flex' : 'none';
        if (transBtn) {
            transBtn.textContent = tab === 'ai-translate' ? '🤖 AI 번역' : '🌐 번역';
            transBtn.onclick = () => (tab === 'ai-translate' ? aiTranslate() : translate());
        }
    }

    async function aiTranslate() {
        if (_busy) return;
        const inp = $('tr-input'), out = $('tr-output');
        const loadEl = $('tr-loading'), insBtn = $('tr-insert-btn');
        const text = inp ? inp.value.trim() : '';
        if (!text) { _setStatus('⚠ 번역할 텍스트를 입력해 주세요.', 'warn'); return; }
        const sl = $('tr-src-lang')?.value, tl = $('tr-tgt-lang')?.value;
        if (sl === tl) { _setStatus('⚠ 원본/번역 언어가 같습니다.', 'warn'); return; }
        const prompt = ($('tr-ai-translate-prompt')?.value || '').trim() || '넌 대학교수, 연구자야 이 번역을 학술연구자에 맞는 용어로 번역해';
        const model = $('tr-model')?.value || 'gemini-2.5-flash';
        const fullPrompt = `${prompt}\n\n다음 텍스트를 ${_LANG_NAMES[sl] || sl}에서 ${_LANG_NAMES[tl] || tl}로 번역해:`;

        _busy = true;
        if (loadEl) loadEl.style.display = 'flex';
        if (out) out.value = 'AI 번역 중…';
        if (insBtn) insBtn.disabled = true;
        _setStatus('');
        try {
            const result = await _callGemini(fullPrompt, text, model);
            _lastResult = result;
            if (out) out.value = result;
            if (insBtn) insBtn.disabled = false;
            _setStatus(`✅ 완료 · ${result.length}자`, 'ok');
        } catch (e) {
            _lastResult = '';
            if (out) out.value = `⚠ ${e.message}`;
            _setStatus('❌ 오류', 'err');
        } finally {
            _busy = false;
            if (loadEl) loadEl.style.display = 'none';
        }
    }

    async function aiWrite() {
        if (_busy) return;
        const inp = $('tr-input'), out = $('tr-output');
        const loadEl = $('tr-loading'), insBtn = $('tr-insert-btn');
        const text = inp ? inp.value.trim() : '';
        if (!text) { _setStatus('⚠ 텍스트를 입력해 주세요.', 'warn'); return; }
        const prompt = ($('tr-ai-write-prompt')?.value || '').trim() || '넌 대학교수, 연구자야 이 번역을 학술연구자에 맞는 글로 다시 써줘. 문장은 ~이다 체로 용어를 학술적용어에 맞게, 대학원이상수준의 글로 써줘';
        const model = $('tr-model-write')?.value || 'gemini-2.5-flash';

        _busy = true;
        if (loadEl) loadEl.style.display = 'flex';
        if (out) out.value = 'AI 글쓰기 중…';
        if (insBtn) insBtn.disabled = true;
        _setStatus('');
        try {
            const result = await _callGemini(prompt, text, model);
            _lastResult = result;
            if (out) out.value = result;
            if (insBtn) insBtn.disabled = false;
            _setStatus(`✅ 완료 · ${result.length}자`, 'ok');
        } catch (e) {
            _lastResult = '';
            if (out) out.value = `⚠ ${e.message}`;
            _setStatus('❌ 오류', 'err');
        } finally {
            _busy = false;
            if (loadEl) loadEl.style.display = 'none';
        }
    }

    async function translate() {
        if (_busy) return;
        const inp = $('tr-input'), out = $('tr-output');
        const loadEl = $('tr-loading'), insBtn = $('tr-insert-btn');
        const srcSel = $('tr-src-lang'), tgtSel = $('tr-tgt-lang');
        const text = inp ? inp.value.trim() : '';
        if (!text) { _setStatus('⚠ 번역할 텍스트를 입력해 주세요.', 'warn'); return; }
        if (!srcSel || !tgtSel) { _setStatus('⚠ 언어 선택 요소를 찾을 수 없습니다.', 'err'); return; }
        const sl = srcSel.value, tl = tgtSel.value;
        if (sl === tl) { _setStatus('⚠ 원본/번역 언어가 같습니다.', 'warn'); return; }

        _busy = true;
        if (loadEl) loadEl.style.display = 'flex';
        if (out) out.value = '번역 중…';
        if (insBtn) insBtn.disabled = true;
        _setStatus('');

        const t0 = Date.now();
        try {
            const result = await _doTranslate(text, sl, tl);
            _lastResult = result;
            if (out) out.value = result;
            if (insBtn) insBtn.disabled = false;
            _setStatus(`✅ 완료 (${((Date.now()-t0)/1000).toFixed(1)}s) · ${result.length}자`, 'ok');
        } catch (e) {
            _lastResult = '';
            const msg = e.message || String(e);
            const hint = msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('CORS')
                ? '네트워크 연결 또는 CORS를 확인하세요. (로컬 파일 실행 시 브라우저가 차단할 수 있습니다)'
                : '네트워크 상태 또는 언어 조합을 확인하세요.';
            if (out) out.value = `⚠ 번역 실패: ${msg}\n${hint}`;
            _setStatus('❌ 오류', 'err');
        } finally {
            _busy = false;
            if (loadEl) loadEl.style.display = 'none';
        }
    }

    function swapLang() {
        const src = $('tr-src-lang'), tgt = $('tr-tgt-lang');
        if (!src || !tgt) return;
        [src.value, tgt.value] = [tgt.value, src.value];
        const inp = $('tr-input'), out = $('tr-output');
        if (inp && _lastResult) {
            const prev = inp.value;
            inp.value = _lastResult;
            if (out) out.value = prev;
            _lastResult = prev;
            _updateCount();
        }
    }

    function insertResult() {
        const out = $('tr-output');
        const txt = out ? out.value.trim() : _lastResult;
        if (!txt) return;
        const ed = $('editor');
        if (!ed) return;
        const mode = ($('tr-insert-mode') || {}).value || 'replace';
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        const orig = ed.value.substring(s, e2);
        const insertTxt = mode === 'replace' ? txt
                  : mode === 'after'   ? orig + txt
                  : mode === 'newline' ? (orig ? orig + '\n' : '') + '\n' + txt
                  : orig + '\n\n> ' + txt;  /* both */
        ed.setRangeText(insertTxt, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        const insertMsg = $('tr-insert-msg');
        if (insertMsg) { insertMsg.textContent = '✔ 에디터에 삽입되었습니다.'; insertMsg.style.display = ''; insertMsg.style.color = 'var(--ok)'; }
        _setStatus('');
        setTimeout(() => { if (insertMsg) { insertMsg.textContent = ''; insertMsg.style.display = 'none'; } hide(); }, 500);
    }

    function copyResult() {
        const out = $('tr-output');
        const txt = out ? out.value.trim() : _lastResult;
        if (!txt) return;
        navigator.clipboard.writeText(txt)
            .then(() => _setStatus('📋 복사되었습니다.', 'ok'))
            .catch(() => {
                const ta = document.createElement('textarea');
                ta.value = txt;
                document.body.appendChild(ta);
                ta.select(); document.execCommand('copy');
                document.body.removeChild(ta);
                _setStatus('📋 복사 완료', 'ok');
            });
    }

    function openBrowser() {
        const inp = $('tr-input');
        const text = inp ? inp.value.trim() : '';
        const sl = $('tr-src-lang').value, tl = $('tr-tgt-lang').value;
        window.open(
            `https://translate.google.com/?sl=${sl}&tl=${tl}&text=${encodeURIComponent(text)}&op=translate`,
            '_blank'
        );
    }

    function clearInput() {
        const inp = $('tr-input');
        if (inp) { inp.value = ''; _updateCount(); }
        _lastResult = '';
        const out = $('tr-output');
        if (out) out.value = '';
        const insBtn = $('tr-insert-btn');
        if (insBtn) insBtn.disabled = true;
        _setStatus('');
    }

    function onInput() { _updateCount(); }

    function onOutputInput() {
        const out = $('tr-output'), insBtn = $('tr-insert-btn');
        if (out) _lastResult = out.value;
        if (insBtn) insBtn.disabled = !(out && out.value.trim());
    }

    /* Ctrl+Enter → 번역/AI */
    document.addEventListener('DOMContentLoaded', () => {
        AppLock.init();
        const inp = $('tr-input');
        if (inp) {
            inp.addEventListener('keydown', e => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    e.preventDefault();
                    if (_currentTab === 'ai-translate') aiTranslate();
                    else if (_currentTab === 'ai-write') aiWrite();
                    else translate();
                }
            });
        }
    });

    return { show, hide, toggleFullscreen, translate, swapLang, insertResult, copyResult, openBrowser, openOriginalAndTranslationInNewWindow, openTranslationInNewWindow, translateText, openBrowserWithText, openTranslationInNewWindowWithText, openOriginalAndTranslationInNewWindowWithText, clearInput, onInput, onOutputInput, switchTab, aiTranslate, aiWrite };
})();
