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

    function _doInsert(includeThinking) {
        const out = $('dr-output');
        let txt = out ? out.value.trim() : _result;
        if (!txt) return;
        if (includeThinking && _thinking && _thinking.trim()) {
            txt = txt + '\n\n--- 생각 ---\n' + _thinking.trim();
        }
        const ed = $('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(txt, s, e2, 'end');
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

    return { show, hide, run, stopRun, runPro, switchTab, toggleMaximize, toggleThinking, toggleNewFile, insertToNewFile, insert, copyResult, copyThinking, clearOutput, openResultInNewWindow, openThinkingInNewWindow, openResultForTranslate, openThinkingForTranslate, thinkingTranslateGoogle, thinkingTranslateResultNewWindow, thinkingTranslateBothNewWindow, loadHistory, filterHistory, loadHistoryItem, renameHistory, deleteHistory, openHistorySaveModal, closeHistorySaveModal, saveHistoryAsZip, saveHistoryBatch, saveHistoryItemToFile, closeThinkingIncludeModal, confirmThinkingInclude, runCiteAiSearch, openCiteAiSearch, applyAiSearchPreset, openPresetTextWindow, applyCiteAiSearchPreset, openCitePresetTextWindow, runCiteAiSearchFromModal, insertFromCiteModal, insertToNewFileFromCiteModal, copyResultFromCiteModal, openResultInNewWindowFromCiteModal, openResultForTranslateFromCiteModal, runDataResearch, applyDataResearchPreset, openDataPresetTextWindow };
})();
window.DeepResearch = DeepResearch;

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