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

/* ═══════════════════════════════════════════════════════════
   CHARMAP — 문자표 (Windows 문자표 스타일 특수문자 삽입)
═══════════════════════════════════════════════════════════ */
const CharMap = (() => {
    let _selected = null;
    let _currentCat = 0;

    const CATS = [
        { name: '자주 사용', chars: [
            { ch: '©', name: '저작권', code: 'U+00A9' },
            { ch: '®', name: '등록상표', code: 'U+00AE' },
            { ch: '™', name: '상표', code: 'U+2122' },
            { ch: '°', name: '도', code: 'U+00B0' },
            { ch: '±', name: '플러스마이너스', code: 'U+00B1' },
            { ch: '×', name: '곱하기', code: 'U+00D7' },
            { ch: '÷', name: '나누기', code: 'U+00F7' },
            { ch: '≈', name: '근사값', code: 'U+2248' },
            { ch: '≠', name: '같지않음', code: 'U+2260' },
            { ch: '≤', name: '이하', code: 'U+2264' },
            { ch: '≥', name: '이상', code: 'U+2265' },
            { ch: '∞', name: '무한대', code: 'U+221E' },
            { ch: '√', name: '루트', code: 'U+221A' },
            { ch: '∑', name: '시그마', code: 'U+2211' },
            { ch: '∏', name: '파이적분', code: 'U+220F' },
            { ch: '∫', name: '적분', code: 'U+222B' },
            { ch: '→', name: '오른쪽화살표', code: 'U+2192' },
            { ch: '←', name: '왼쪽화살표', code: 'U+2190' },
            { ch: '↑', name: '위쪽화살표', code: 'U+2191' },
            { ch: '↓', name: '아래화살표', code: 'U+2193' },
            { ch: '•', name: '점(불릿)', code: 'U+2022' },
            { ch: '…', name: '말줄임표', code: 'U+2026' },
            { ch: '「', name: '왼낫표', code: 'U+300C' },
            { ch: '」', name: '오른낫표', code: 'U+300D' },
            { ch: '『', name: '이중왼낫표', code: 'U+300E' },
            { ch: '』', name: '이중오른낫표', code: 'U+300F' },
            { ch: '【', name: '굵은왼괄호', code: 'U+3010' },
            { ch: '】', name: '굵은오른괄호', code: 'U+3011' },
            { ch: '§', name: '섹션기호', code: 'U+00A7' },
            { ch: '¶', name: '단락기호', code: 'U+00B6' },
            { ch: '†', name: '단검표', code: 'U+2020' },
            { ch: '‡', name: '이중단검표', code: 'U+2021' },
        ]},
        { name: '화살표', chars: [
            { ch: '→', name: '오른쪽', code: 'U+2192' }, { ch: '←', name: '왼쪽', code: 'U+2190' },
            { ch: '↑', name: '위쪽', code: 'U+2191' }, { ch: '↓', name: '아래쪽', code: 'U+2193' },
            { ch: '↔', name: '좌우', code: 'U+2194' }, { ch: '↕', name: '상하', code: 'U+2195' },
            { ch: '↖', name: '왼위', code: 'U+2196' }, { ch: '↗', name: '오른위', code: 'U+2197' },
            { ch: '↘', name: '오른아래', code: 'U+2198' }, { ch: '↙', name: '왼아래', code: 'U+2199' },
            { ch: '⇒', name: '오른쪽이중', code: 'U+21D2' }, { ch: '⇐', name: '왼쪽이중', code: 'U+21D0' },
            { ch: '⇑', name: '위쪽이중', code: 'U+21D1' }, { ch: '⇓', name: '아래이중', code: 'U+21D3' },
            { ch: '⇔', name: '좌우이중', code: 'U+21D4' }, { ch: '⇕', name: '상하이중', code: 'U+21D5' },
            { ch: '➡', name: '채운오른쪽', code: 'U+27A1' }, { ch: '⬅', name: '채운왼쪽', code: 'U+2B05' },
            { ch: '⬆', name: '채운위쪽', code: 'U+2B06' }, { ch: '⬇', name: '채운아래', code: 'U+2B07' },
            { ch: '↩', name: '되돌아', code: 'U+21A9' }, { ch: '↪', name: '앞으로', code: 'U+21AA' },
            { ch: '↻', name: '시계방향', code: 'U+21BB' }, { ch: '↺', name: '반시계', code: 'U+21BA' },
        ]},
        { name: '수학 기호', chars: [
            { ch: '±', name: '플러스마이너스', code: 'U+00B1' }, { ch: '∓', name: '마이너스플러스', code: 'U+2213' },
            { ch: '×', name: '곱하기', code: 'U+00D7' }, { ch: '÷', name: '나누기', code: 'U+00F7' },
            { ch: '√', name: '제곱근', code: 'U+221A' }, { ch: '∛', name: '세제곱근', code: 'U+221B' },
            { ch: '∜', name: '네제곱근', code: 'U+221C' }, { ch: '∞', name: '무한대', code: 'U+221E' },
            { ch: '≈', name: '근사', code: 'U+2248' }, { ch: '≠', name: '같지않음', code: 'U+2260' },
            { ch: '≡', name: '항등', code: 'U+2261' }, { ch: '≤', name: '이하', code: 'U+2264' },
            { ch: '≥', name: '이상', code: 'U+2265' }, { ch: '≪', name: '훨씬작음', code: 'U+226A' },
            { ch: '≫', name: '훨씬큼', code: 'U+226B' }, { ch: '∑', name: '합계', code: 'U+2211' },
            { ch: '∏', name: '곱', code: 'U+220F' }, { ch: '∫', name: '적분', code: 'U+222B' },
            { ch: '∬', name: '이중적분', code: 'U+222C' }, { ch: '∂', name: '편미분', code: 'U+2202' },
            { ch: '∇', name: '나블라', code: 'U+2207' }, { ch: '∈', name: '원소', code: 'U+2208' },
            { ch: '∉', name: '비원소', code: 'U+2209' }, { ch: '⊂', name: '부분집합', code: 'U+2282' },
            { ch: '⊃', name: '초집합', code: 'U+2283' }, { ch: '∪', name: '합집합', code: 'U+222A' },
            { ch: '∩', name: '교집합', code: 'U+2229' }, { ch: '∅', name: '공집합', code: 'U+2205' },
            { ch: '∝', name: '비례', code: 'U+221D' }, { ch: '⊕', name: 'XOR', code: 'U+2295' },
            { ch: 'α', name: '알파', code: 'U+03B1' }, { ch: 'β', name: '베타', code: 'U+03B2' },
            { ch: 'γ', name: '감마', code: 'U+03B3' }, { ch: 'δ', name: '델타', code: 'U+03B4' },
            { ch: 'ε', name: '엡실론', code: 'U+03B5' }, { ch: 'θ', name: '세타', code: 'U+03B8' },
            { ch: 'λ', name: '람다', code: 'U+03BB' }, { ch: 'μ', name: '뮤', code: 'U+03BC' },
            { ch: 'π', name: '파이', code: 'U+03C0' }, { ch: 'σ', name: '시그마(소)', code: 'U+03C3' },
            { ch: 'φ', name: '파이(소)', code: 'U+03C6' }, { ch: 'ω', name: '오메가(소)', code: 'U+03C9' },
            { ch: 'Γ', name: '감마(대)', code: 'U+0393' }, { ch: 'Δ', name: '델타(대)', code: 'U+0394' },
            { ch: 'Σ', name: '시그마(대)', code: 'U+03A3' }, { ch: 'Ω', name: '오메가(대)', code: 'U+03A9' },
        ]},
        { name: '도형·기호', chars: [
            { ch: '■', name: '채운사각', code: 'U+25A0' }, { ch: '□', name: '빈사각', code: 'U+25A1' },
            { ch: '▪', name: '작은채운사각', code: 'U+25AA' }, { ch: '▫', name: '작은빈사각', code: 'U+25AB' },
            { ch: '▲', name: '위삼각', code: 'U+25B2' }, { ch: '▼', name: '아래삼각', code: 'U+25BC' },
            { ch: '◀', name: '왼삼각', code: 'U+25C0' }, { ch: '▶', name: '오른삼각', code: 'U+25B6' },
            { ch: '●', name: '채운원', code: 'U+25CF' }, { ch: '○', name: '빈원', code: 'U+25CB' },
            { ch: '◉', name: '과녁원', code: 'U+25C9' }, { ch: '◎', name: '이중원', code: 'U+25CE' },
            { ch: '★', name: '채운별', code: 'U+2605' }, { ch: '☆', name: '빈별', code: 'U+2606' },
            { ch: '◆', name: '채운다이아', code: 'U+25C6' }, { ch: '◇', name: '빈다이아', code: 'U+25C7' },
            { ch: '♦', name: '다이아카드', code: 'U+2666' }, { ch: '♠', name: '스페이드', code: 'U+2660' },
            { ch: '♥', name: '하트', code: 'U+2665' }, { ch: '♣', name: '클럽', code: 'U+2663' },
            { ch: '✓', name: '체크', code: 'U+2713' }, { ch: '✔', name: '굵은체크', code: 'U+2714' },
            { ch: '✗', name: 'X표시', code: 'U+2717' }, { ch: '✘', name: '굵은X', code: 'U+2718' },
            { ch: '⊙', name: '점원', code: 'U+2299' }, { ch: '⊚', name: '이중점원', code: 'U+229A' },
            { ch: '⊞', name: '더하기상자', code: 'U+229E' }, { ch: '⊟', name: '빼기상자', code: 'U+229F' },
        ]},
        { name: '구두점·기타', chars: [
            { ch: '—', name: '줄표(em)', code: 'U+2014' }, { ch: '–', name: '반줄표(en)', code: 'U+2013' },
            { ch: '…', name: '말줄임표', code: 'U+2026' }, { ch: '·', name: '가운뎃점', code: 'U+00B7' },
            { ch: '\u2010', name: '하이픈', code: 'U+2010' }, { ch: '\u201C', name: '왼큰따옴표', code: 'U+201C' },
            { ch: '\u201D', name: '오른큰따옴표', code: 'U+201D' }, { ch: '\u2018', name: '왼작은따옴표', code: 'U+2018' },
            { ch: '\u2019', name: '오른작은따옴표', code: 'U+2019' }, { ch: '\u00AB', name: '이중꺾쇠왼', code: 'U+00AB' },
            { ch: '\u2019', name: '오른작은따옴표', code: 'U+2019' }, { ch: '\u00AB', name: '이중꺾쇠왼', code: 'U+00AB' },
            { ch: '»', name: '이중꺾쇠오른', code: 'U+00BB' }, { ch: '‹', name: '꺾쇠왼', code: 'U+2039' },
            { ch: '›', name: '꺾쇠오른', code: 'U+203A' }, { ch: '§', name: '섹션', code: 'U+00A7' },
            { ch: '¶', name: '단락', code: 'U+00B6' }, { ch: '†', name: '단검표', code: 'U+2020' },
            { ch: '‡', name: '이중단검', code: 'U+2021' }, { ch: '※', name: '참고', code: 'U+203B' },
            { ch: '′', name: '프라임(분)', code: 'U+2032' }, { ch: '″', name: '이중프라임(초)', code: 'U+2033' },
            { ch: '°', name: '도', code: 'U+00B0' }, { ch: '℃', name: '섭씨', code: 'U+2103' },
            { ch: '℉', name: '화씨', code: 'U+2109' }, { ch: '㎡', name: '제곱미터', code: 'U+33A1' },
            { ch: '㎞', name: '킬로미터', code: 'U+339E' }, { ch: '㎝', name: '센티미터', code: 'U+339D' },
            { ch: '㎜', name: '밀리미터', code: 'U+339C' }, { ch: '㎏', name: '킬로그램', code: 'U+338F' },
        ]},
        { name: '통화·특수', chars: [
            { ch: '₩', name: '원', code: 'U+20A9' }, { ch: '$', name: '달러', code: 'U+0024' },
            { ch: '€', name: '유로', code: 'U+20AC' }, { ch: '£', name: '파운드', code: 'U+00A3' },
            { ch: '¥', name: '엔', code: 'U+00A5' }, { ch: '¢', name: '센트', code: 'U+00A2' },
            { ch: '₿', name: '비트코인', code: 'U+20BF' }, { ch: '฿', name: '바트', code: 'U+0E3F' },
            { ch: '©', name: '저작권', code: 'U+00A9' }, { ch: '®', name: '등록상표', code: 'U+00AE' },
            { ch: '™', name: '상표', code: 'U+2122' }, { ch: '℠', name: '서비스마크', code: 'U+2120' },
            { ch: '☎', name: '전화', code: 'U+260E' }, { ch: '✉', name: '이메일', code: 'U+2709' },
            { ch: '♻', name: '재활용', code: 'U+267B' }, { ch: '⚠', name: '경고', code: 'U+26A0' },
            { ch: '☐', name: '빈체크박스', code: 'U+2610' }, { ch: '☑', name: '체크박스', code: 'U+2611' },
            { ch: '☒', name: 'X체크박스', code: 'U+2612' }, { ch: '♂', name: '남성', code: 'U+2642' },
            { ch: '♀', name: '여성', code: 'U+2640' }, { ch: '⚡', name: '번개', code: 'U+26A1' },
        ]},
        { name: '학술·연구', chars: [
            { ch: 'p', name: 'p값', code: 'U+0070' }, { ch: 'F', name: 'F통계량', code: 'U+0046' },
            { ch: 't', name: 't통계량', code: 'U+0074' }, { ch: 'χ', name: '카이(소)', code: 'U+03C7' },
            { ch: 'χ²', name: '카이제곱', code: 'U+03C7 U+00B2' }, { ch: 'η²', name: '에타제곱', code: 'U+03B7 U+00B2' },
            { ch: 'ω²', name: '오메가제곱', code: 'U+03C9 U+00B2' }, { ch: 'β', name: '베타계수', code: 'U+03B2' },
            { ch: 'r', name: '상관계수', code: 'U+0072' }, { ch: 'R²', name: 'R제곱', code: 'U+0052 U+00B2' },
            { ch: 'M', name: '평균', code: 'U+004D' }, { ch: 'SD', name: '표준편차', code: '' },
            { ch: 'SE', name: '표준오차', code: '' }, { ch: 'CI', name: '신뢰구간', code: '' },
            { ch: '¹', name: '위첨자1', code: 'U+00B9' }, { ch: '²', name: '위첨자2', code: 'U+00B2' },
            { ch: '³', name: '위첨자3', code: 'U+00B3' }, { ch: '⁴', name: '위첨자4', code: 'U+2074' },
            { ch: '₁', name: '아래첨자1', code: 'U+2081' }, { ch: '₂', name: '아래첨자2', code: 'U+2082' },
            { ch: '₃', name: '아래첨자3', code: 'U+2083' }, { ch: '₄', name: '아래첨자4', code: 'U+2084' },
            { ch: 'Å', name: '옹스트롬', code: 'U+00C5' }, { ch: '‰', name: '퍼밀', code: 'U+2030' },
        ]},
    ];

    let _allChars = [];
    CATS.forEach(cat => { _allChars = _allChars.concat(cat.chars.map(c => ({...c, cat: cat.name}))); });

    function _buildCatTabs() {
        const el2 = document.getElementById('cm-cat-tabs');
        if (!el2) return;
        el2.innerHTML = '';
        CATS.forEach((cat, i) => {
            const btn = document.createElement('button');
            btn.className = 'btn btn-g btn-sm' + (i === _currentCat ? ' active' : '');
            btn.textContent = cat.name;
            btn.style.cssText = 'font-size:10px;padding:2px 8px;' + (i === _currentCat ? 'background:var(--ac);color:#fff;border-color:var(--ac)' : '');
            btn.onclick = () => { _currentCat = i; document.getElementById('cm-search').value = ''; _buildCatTabs(); _renderChars(CATS[i].chars); };
            el2.appendChild(btn);
        });
    }

    function _renderChars(chars) {
        const grid = document.getElementById('cm-grid');
        if (!grid) return;
        grid.innerHTML = '';
        chars.forEach(item => {
            const div = document.createElement('div');
            div.className = 'cm-char-cell';
            div.textContent = item.ch;
            div.title = item.name + ' ' + item.code;
            div.onclick = () => _select(item);
            div.ondblclick = () => { _select(item); insert(); };
            grid.appendChild(div);
        });
    }

    function _select(item) {
        _selected = item;
        const prev = document.getElementById('cm-preview');
        const name = document.getElementById('cm-name');
        const code = document.getElementById('cm-code');
        const btn  = document.getElementById('cm-insert-btn');
        if (prev) prev.textContent = item.ch;
        if (name) name.textContent = item.name;
        if (code) code.textContent = item.code;
        if (btn)  btn.disabled = false;
        /* 선택 표시 */
        document.querySelectorAll('.cm-char-cell.sel').forEach(c => c.classList.remove('sel'));
        event.currentTarget && event.currentTarget.classList.add('sel');
    }

    function search(q) {
        if (!q.trim()) { _renderChars(CATS[_currentCat].chars); return; }
        const kw = q.trim().toLowerCase();
        const res = _allChars.filter(c =>
            c.name.toLowerCase().includes(kw) ||
            c.ch.includes(q) ||
            (c.code && c.code.toLowerCase().includes(kw))
        );
        _renderChars(res);
    }

    function insert() {
        if (!_selected) return;
        const ed = document.getElementById('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(_selected.ch, s, e2, 'end');
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined') App.render();
        hide();
    }

    function show() {
        const modal = document.getElementById('charmap-modal');
        if (!modal) return;
        modal.classList.add('vis');
        _buildCatTabs();
        _renderChars(CATS[_currentCat].chars);
        setTimeout(() => { const s = document.getElementById('cm-search'); if(s) s.focus(); }, 50);
    }

    function hide() {
        const modal = document.getElementById('charmap-modal');
        if (modal) modal.classList.remove('vis');
    }

    return { show, hide, search, insert };
})();

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

/* ═══════════════════════════════════════════════════════════
   ScrollSync — 에디터 ↔ 미리보기 스크롤 동기화
   에디터 스크롤 비율을 preview-container에 반영
═══════════════════════════════════════════════════════════ */
/* ScrollSync는 SS 모듈(헤딩 기반)이 담당 — 별도 구현 불필요 */
const ScrollSync = (() => {
    function onEditor() { /* SS.init()에서 이미 에디터 scroll 이벤트 처리 */ }
    function onPreview() { /* SS.init()에서 이미 미리보기 scroll 이벤트 처리 */ }
    function init() { /* SS.init()에 위임 */ }
    return { onEditor, onPreview, init };
})();


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