    function _renderResult() {
        const wrap = el('aiimg-result-images');
        if (!wrap) return;
        wrap.innerHTML = '';
        const rw = el('aiimg-result-wrap');
        const empty = el('aiimg-empty-result');
        if (_resultImages.length) {
            if (rw) rw.style.display = 'block';
            if (empty) empty.style.display = 'none';
            _resultImages.forEach((dataUrl, i) => {
                const wrapper = document.createElement('div');
                wrapper.style.cssText = 'position:relative;display:inline-block';
                const img = document.createElement('img');
                img.src = dataUrl;
                img.style.cssText = 'max-width:100%;max-height:400px;width:auto;object-fit:contain;border-radius:8px;border:1px solid var(--bd);cursor:pointer;display:block';
                img.title = '클릭: 다운로드 | 더블클릭: 크게 보기';
                img.dataset.index = String(i);
                img.onclick = (e) => {
                    if (e.detail === 2) {
                        openResultInNewWindow(dataUrl);
                        return;
                    }
                    const a = document.createElement('a');
                    a.href = dataUrl;
                    a.download = `aiimg-${Date.now()}-${i}.png`;
                    a.click();
                };
                wrapper.appendChild(img);
                wrap.appendChild(wrapper);
            });
            const centerCrop = document.getElementById('aiimg-center-crop-btn');
            const centerBig = document.getElementById('aiimg-center-big-btn');
            if (centerCrop) centerCrop.disabled = false;
            if (centerBig) centerBig.disabled = false;
        } else {
            if (rw) rw.style.display = 'none';
            if (empty) empty.style.display = 'flex';
            const centerCrop = document.getElementById('aiimg-center-crop-btn');
            const centerBig = document.getElementById('aiimg-center-big-btn');
            if (centerCrop) centerCrop.disabled = true;
            if (centerBig) centerBig.disabled = true;
        }
    }

    async function generate() {
        if (_busy) return;
        const promptEl = el('aiimg-prompt');
        let prompt = promptEl ? promptEl.value.trim() : '';
        if (!prompt) { alert('프롬프트를 입력하세요.'); return; }
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) { alert('AI API 키를 설정에서 입력해 주세요.'); return; }
        const textModelEl = el('aiimg-text-model');
        const textModelId = textModelEl && textModelEl.value ? textModelEl.value.trim() : '';
        if (textModelId) {
            try {
                const refineUrl = `https://generativelanguage.googleapis.com/v1beta/models/${textModelId}:generateContent?key=${encodeURIComponent(key)}`;
                const refineBody = {
                    contents: [{
                        role: 'user',
                        parts: [{ text: `다음 사용자 요청을 이미지 생성 AI에 전달할 수 있도록, 구체적이고 시각적으로 묘사된 단일 프롬프트로만 변환해 주세요. 다른 설명이나 접두사 없이 변환된 프롬프트 한 개만 출력하세요.\n\n사용자 요청:\n${prompt}` }]
                    }],
                    generationConfig: { temperature: 0.4, maxOutputTokens: 1024 }
                };
                const refineRes = await fetch(refineUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(refineBody),
                    signal: AbortSignal.timeout(30000)
                });
                const refineData = await refineRes.json();
                if (refineRes.ok && refineData.candidates?.[0]?.content?.parts?.[0]?.text) {
                    const enhanced = String(refineData.candidates[0].content.parts[0].text).trim();
                    if (enhanced) prompt = enhanced;
                }
            } catch (e) {
                console.warn('텍스트 모델 프롬프트 보강 실패, 원본 사용:', e);
            }
        }
        const modelId = (el('aiimg-model') && el('aiimg-model').value) || 'gemini-2.0-flash-exp-image-generation';
        _busy = true;
        _currentPrompt = prompt;
        const loadingEl = el('aiimg-loading');
        if (loadingEl) loadingEl.style.display = 'block';
        el('aiimg-generate-btn').disabled = true;
        _setProgress(0);
        let progressInterval = setInterval(() => {
            const pctEl = document.getElementById('aiimg-progress-pct');
            if (!pctEl) return;
            const current = parseInt(pctEl.textContent, 10) || 0;
            if (current >= 90) return;
            _setProgress(Math.min(current + 5, 90));
        }, 500);
        const contents = [];
        if (_seedDataUrl) {
            const base64 = _seedDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const mime = _seedDataUrl.match(/^data:(image\/\w+);/);
            contents.push({
                inlineData: { mimeType: mime ? mime[1] : 'image/png', data: base64 }
            });
        }
        contents.push({ text: prompt });
        const promptHasRatio = /비율|\d+\s*:\s*\d+/.test(prompt);
        let aspectHint = '';
        if (!promptHasRatio && _seedAspectRatio) aspectHint = '\n[이미지 비율: ' + _seedAspectRatio + '로 생성해 주세요.]';
        contents[contents.length - 1].text = prompt + aspectHint;
        const personCb = document.getElementById('aiimg-fix-person-cb');
        const outfitCb = document.getElementById('aiimg-fix-outfit-cb');
        let prefix = '';
        if (personCb && personCb.checked && _analysisResult.face) {
            prefix += '[인물 고정 - 아래 특징 유지]\n' + _analysisResult.face + '\n\n';
        }
        if (outfitCb && outfitCb.checked && _analysisResult.outfit) {
            prefix += '[복장 고정 - 아래 의상 유지]\n' + _analysisResult.outfit + '\n\n';
        }
        if (prefix) contents[contents.length - 1].text = prefix + contents[contents.length - 1].text;
        const useOrigin = document.getElementById('aiimg-tryon-ref-origin') && document.getElementById('aiimg-tryon-ref-origin').checked;
        const tryOnDataUrl = useOrigin ? _virtualTryOnDataUrl : _virtualTryOnExtractedDataUrl;
        if (tryOnDataUrl) {
            const vbase64 = tryOnDataUrl.replace(/^data:image\/\w+;base64,/, '');
            const vmime = tryOnDataUrl.match(/^data:(image\/\w+);/);
            contents.push({
                inlineData: { mimeType: vmime ? vmime[1] : 'image/png', data: vbase64 }
            });
            contents.push({ text: useOrigin ? '위 이미지를 참고하여 생성해 주세요.' : '위 옷/스타일을 적용한 이미지로 생성해 주세요.' });
        }
        const body = {
            contents: [{ role: 'user', parts: contents }],
            generationConfig: {
                responseModalities: ['TEXT', 'IMAGE'],
                responseMimeType: 'text/plain'
            }
        };
        try {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${encodeURIComponent(key)}`;
            const r = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                signal: AbortSignal.timeout(120000)
            });
            const data = await r.json();
            if (!r.ok) throw new Error(data.error?.message || `HTTP ${r.status}`);
            const parts = data.candidates?.[0]?.content?.parts || [];
            const newImages = [];
            parts.forEach(p => {
                if (p.inlineData && p.inlineData.data) {
                    const mime = p.inlineData.mimeType || 'image/png';
                    newImages.push('data:' + mime + ';base64,' + p.inlineData.data);
                }
            });
            if (newImages.length > 0) {
                _resultImages = newImages;
                _renderResult();
                const record = {
                    id: 'aiimg-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
                    prompt,
                    imageData: newImages,
                    createdAt: Date.now()
                };
                await _add(record);
                _historyCache.unshift(record);
                _renderHistory();
            } else {
                _resultImages = [];
                _renderResult();
                alert('이미지가 생성되지 않았습니다. 다른 모델이나 프롬프트를 시도해 보세요.');
            }
        } catch (e) {
            _resultImages = [];
            _renderResult();
            alert('오류: ' + (e.message || String(e)));
        } finally {
            _busy = false;
            clearInterval(progressInterval);
            _setProgress(100);
            setTimeout(() => {
                const loadingEl = el('aiimg-loading');
                if (loadingEl) loadingEl.style.display = 'none';
                _setProgress(0);
            }, 400);
            el('aiimg-generate-btn').disabled = false;
        }
    }
    function _setProgress(pct) {
        const pctEl = document.getElementById('aiimg-progress-pct');
        const barEl = document.getElementById('aiimg-progress-bar');
        if (pctEl) pctEl.textContent = pct + '%';
        if (barEl) barEl.style.width = pct + '%';
    }

    function _renderHistory() {
        const list = el('aiimg-history-list');
        if (!list) return;
        list.textContent = '';
        list.removeAttribute('data-empty');
        if (!_historyCache.length) {
            list.setAttribute('data-empty', '생성된 이미지가 여기에 저장됩니다.');
            return;
        }
        _historyCache.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
        _historyCache.forEach(item => {
            const div = document.createElement('div');
            div.className = 'dr-history-item';
            div.style.cssText = 'padding:6px;margin-bottom:6px;border-radius:6px;border:1px solid var(--bd);cursor:pointer;background:var(--bg4);position:relative';
            const delBtn = document.createElement('button');
            delBtn.type = 'button';
            delBtn.className = 'btn btn-g btn-sm';
            delBtn.style.cssText = 'position:absolute;top:4px;left:4px;font-size:10px;padding:2px 6px;z-index:2';
            delBtn.textContent = '×';
            delBtn.title = '이 항목 삭제';
            delBtn.onclick = (e) => { e.stopPropagation(); removeHistoryItem(item.id); };
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;align-items:flex-start;gap:6px';
            const thumbWrap = document.createElement('div');
            thumbWrap.style.cssText = 'flex:1;min-width:0;height:72px;background:var(--bg3);border-radius:4px;overflow:hidden;display:flex;align-items:center;justify-content:center';
            const img = document.createElement('img');
            img.src = Array.isArray(item.imageData) && item.imageData[0] ? item.imageData[0] : '';
            img.style.cssText = 'max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;display:block';
            const cap = document.createElement('div');
            cap.style.cssText = 'font-size:10px;color:var(--tx3);margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
            cap.textContent = (item.prompt || '').slice(0, 24) + (item.prompt && item.prompt.length > 24 ? '…' : '');
            thumbWrap.appendChild(img);
            const col = document.createElement('div');
            col.style.cssText = 'flex:1;min-width:0';
            col.appendChild(thumbWrap);
            col.appendChild(cap);
            row.appendChild(col);
            div.appendChild(delBtn);
            div.appendChild(row);
            div.onclick = () => {
                _resultImages = Array.isArray(item.imageData) ? [...item.imageData] : [];
                _currentPrompt = item.prompt || '';
                if (el('aiimg-prompt')) el('aiimg-prompt').value = _currentPrompt;
                _renderResult();
            };
            list.appendChild(div);
        });
    }
    async function loadHistory() {
        try {
            _historyCache = await _getAll();
        } catch (_) {
            _historyCache = [];
        }
        _renderHistory();
    }
    async function clearAllHistory() {
        if (!_historyCache.length) return;
        if (!confirm('히스토리를 모두 삭제할까요?')) return;
        try {
            await _clearAll();
            _historyCache = [];
            _renderHistory();
        } catch (e) {
            alert('삭제 실패: ' + (e.message || String(e)));
        }
    }
    async function removeHistoryItem(id) {
        try {
            await _delete(id);
            _historyCache = _historyCache.filter(item => item.id !== id);
            _renderHistory();
        } catch (e) {
            alert('삭제 실패: ' + (e.message || String(e)));
        }
    }

    function downloadAll() {
        _resultImages.forEach((dataUrl, i) => {
            const a = document.createElement('a');
            a.href = dataUrl;
            a.download = `aiimg-${Date.now()}-${i}.png`;
            a.click();
        });
    }
    function downloadZip() {
        if (typeof JSZip === 'undefined') { alert('ZIP 라이브러리를 불러올 수 없습니다.'); return; }
        const zip = new JSZip();
        _resultImages.forEach((dataUrl, i) => {
            const base64 = dataUrl.replace(/^data:image\/\w+;base64,/, '');
            zip.file(`aiimg-${i + 1}.png`, base64, { base64: true });
        });
        zip.generateAsync({ type: 'blob' }).then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `aiimg-${Date.now()}.zip`;
            a.click();
            URL.revokeObjectURL(a.href);
        });
    }
    function downloadProject() {
        if (typeof JSZip === 'undefined') { alert('ZIP 라이브러리를 불러올 수 없습니다.'); return; }
        const project = {
            version: 1,
            prompt: _currentPrompt,
            modelId: (el('aiimg-model') && el('aiimg-model').value) || '',
            seedImage: _seedDataUrl || null,
            results: _resultImages.map((dataUrl, i) => ({ index: i, data: dataUrl })),
            createdAt: Date.now()
        };
        const zip = new JSZip();
        zip.file('project.json', JSON.stringify(project, null, 2));
        _resultImages.forEach((dataUrl, i) => {
            const base64 = dataUrl.replace(/^data:image\/\w+;base64,/, '');
            zip.file(`image-${i + 1}.png`, base64, { base64: true });
        });
        zip.generateAsync({ type: 'blob' }).then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `aiimg-project-${Date.now()}.mdp`;
            a.click();
            URL.revokeObjectURL(a.href);
        });
    }

    function insertToEditor() {
        const dataUrl = _resultImages[0];
        if (!dataUrl) { alert('삽입할 결과 이미지가 없습니다.'); return; }
        const ed = typeof ED !== 'undefined' && ED.ed ? ED.ed() : null;
        if (!ed) { alert('에디터를 찾을 수 없습니다.'); return; }
        const alt = 'AI 이미지';
        const s = ed.selectionStart, e = ed.selectionEnd;
        ins(ed, s, e, `![${alt}](${dataUrl})`);
        if (typeof ImgStore !== 'undefined') ImgStore.save(dataUrl, alt);
        if (typeof App !== 'undefined' && App.render) App.render();
        if (typeof US !== 'undefined' && US.snap) US.snap();
    }
    function insertToNewFile() {
        const dataUrl = _resultImages[0];
        if (!dataUrl) { alert('삽입할 결과 이미지가 없습니다.'); return; }
        const title = '이미지-' + new Date().toISOString().slice(0, 10);
        if (typeof TM !== 'undefined' && TM.newTab) TM.newTab(title, `![AI 이미지](${dataUrl})`, 'md');
        if (typeof ImgStore !== 'undefined') ImgStore.save(dataUrl, 'AI 이미지');
    }
    function insertSeedToEditor() {
        if (!_seedDataUrl) { alert('삽입할 시드 이미지가 없습니다.'); return; }
        const ed = typeof ED !== 'undefined' && ED.ed ? ED.ed() : null;
        if (!ed) { alert('에디터를 찾을 수 없습니다.'); return; }
        const alt = '시드 이미지';
        const s = ed.selectionStart, e = ed.selectionEnd;
        ins(ed, s, e, `![${alt}](${_seedDataUrl})`);
        if (typeof ImgStore !== 'undefined') ImgStore.save(_seedDataUrl, alt);
        if (typeof App !== 'undefined' && App.render) App.render();
        if (typeof US !== 'undefined' && US.snap) US.snap();
    }
    function insertSeedToNewFile() {
        if (!_seedDataUrl) { alert('삽입할 시드 이미지가 없습니다.'); return; }
        const title = '이미지-' + new Date().toISOString().slice(0, 10);
        if (typeof TM !== 'undefined' && TM.newTab) TM.newTab(title, `![시드 이미지](${_seedDataUrl})`, 'md');
        if (typeof ImgStore !== 'undefined') ImgStore.save(_seedDataUrl, '시드 이미지');
    }
    function insertAnalysisToEditor() {
        const analysisEl = document.getElementById('aiimg-analysis-text');
        const text = (analysisEl && analysisEl.textContent || '').trim();
        if (!text) { alert('삽입할 분석 결과가 없습니다.'); return; }
        const ed = typeof ED !== 'undefined' && ED.ed ? ED.ed() : null;
        if (!ed) { alert('에디터를 찾을 수 없습니다.'); return; }
        const s = ed.selectionStart, e = ed.selectionEnd;
        ins(ed, s, e, '\n\n' + text + '\n\n');
        if (typeof App !== 'undefined' && App.render) App.render();
        if (typeof US !== 'undefined' && US.snap) US.snap();
    }

    return {
        switchTab, toggleMaximize, applyPreset, applyMenuType, sendAnalysisToPrompt, onSeedFile, clearSeed,
        openCropUpload, openCropEdit, openTryOnCropEdit, openTryOnExtractedCropEdit,
        generate, setResultAsSeed, downloadAll, downloadZip, downloadProject, loadHistory,
        insertToEditor, insertToNewFile, insertSeedToEditor, insertSeedToNewFile, insertAnalysisToEditor,
        resetModal, clearAllHistory, removeHistoryItem,
        cropCurrentResult, openCurrentResultInNewWindow, openSeedInNewWindow,
        analyzeSeedImage, onVirtualTryOnFile, clearVirtualTryOn, extractClothingForTryOn, openTryOnImageInNewWindow
    };
})();
window.AiImage = AiImage;

let lastCodeLang = 'python';// track last used language for Alt+C

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

/* ═══════════════════════════════════════════════════════════
   EDITOR CURRENT LINE HIGHLIGHT (아주 투명한 현재 줄 표시)
═══════════════════════════════════════════════════════════ */
const EditorLineHighlight = (() => {
    const STORAGE_KEY = 'mdpro_editor_line_highlight';
    let enabled = true;

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return true; }
    }

    function updateUI() {
        enabled = isEnabled();
        const hl = document.getElementById('editor-line-highlight');
        const btn = document.getElementById('hk-line-highlight-btn');
        if (hl) hl.classList.toggle('vis', enabled);
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
    }

    function updateHighlight() {
        const hl = document.getElementById('editor-line-highlight');
        const ed = document.getElementById('editor');
        if (!hl || !ed || !enabled) return;
        const text = ed.value.substring(0, ed.selectionStart);
        const lineIndex = (text.match(/\n/g) || []).length;
        const style = window.getComputedStyle(ed);
        const lineHeight = parseFloat(style.lineHeight) || 21;
        const paddingTop = parseFloat(style.paddingTop) || 12;
        const paddingLeft = parseFloat(style.paddingLeft) || 14;
        const paddingRight = parseFloat(style.paddingRight) || 14;
        const top = paddingTop + lineIndex * lineHeight - ed.scrollTop;
        hl.style.height = lineHeight + 'px';
        hl.style.top = top + 'px';
        hl.style.left = paddingLeft + 'px';
        hl.style.right = paddingRight + 'px';
    }

    function toggle() {
        try {
            enabled = isEnabled();
            enabled = !enabled;
            localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off');
        } catch (e) {}
        updateUI();
        if (enabled) updateHighlight();
    }

    function init() {
        updateUI();
        const ed = document.getElementById('editor');
        if (!ed) return;
        const run = () => { if (enabled) updateHighlight(); };
        ed.addEventListener('scroll', run, { passive: true });
        ed.addEventListener('click', run);
        ed.addEventListener('keyup', run);
        ed.addEventListener('input', run);
        document.addEventListener('selectionchange', () => { if (document.activeElement === ed) run(); });
        if (enabled) updateHighlight();
    }

    return { toggle, init, updateHighlight, isEnabled, updateUI };
})();

/* ═══════════════════════════════════════════════════════════
   EDITOR AUTO PAIR — ( ) [ ] " " ' ' 자동쌍 & 선택 시 감싸기
═══════════════════════════════════════════════════════════ */
const EditorAutoPair = (() => {
    const STORAGE_KEY = 'mdpro_editor_auto_pair';