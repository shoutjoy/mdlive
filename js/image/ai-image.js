/* AiImage - 이미지 모달 내 AI 이미지 탭 -> js/image/ai-image.js
   의존: el, AiApiKey, _showImgpv, ImgStore, ED, ins, App, US, TM, JSZip */

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
                if (ev.source && !ev.source.closed && img) ev.source.postMessage({ type: 'crop', image: img }, '*');
                return;
            }
            if (!ev.data || ev.data.type !== 'aiimg-cropped' || !ev.data.dataUrl) return;
            window._mdliveCropPending = null;
            if (ev.source && !ev.source.closed) ev.source.postMessage({ type: 'crop-applied' }, '*');
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
                    saveCropResultToHistory();
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
    async function saveCropResultToHistory() {
        if (!_resultImages.length) return;
        const record = {
            id: 'aiimg-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
            prompt: '크롭 결과',
            imageData: [..._resultImages],
            createdAt: Date.now()
        };
        try {
            await _add(record);
            _historyCache.unshift(record);
            _renderHistory();
        } catch (e) {
            console.warn('크롭 결과 저장 실패:', e);
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
    function downloadCurrentToPc() {
        const dataUrl = _resultImages[0];
        if (!dataUrl) { alert('다운로드할 결과 이미지가 없습니다.'); return; }
        const a = document.createElement('a');
        a.href = dataUrl;
        a.download = `aiimg-${Date.now()}.png`;
        a.click();
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
        generate, setResultAsSeed, downloadAll, downloadZip, downloadProject, downloadCurrentToPc, loadHistory,
        insertToEditor, insertToNewFile, insertSeedToEditor, insertSeedToNewFile, insertAnalysisToEditor,
        resetModal, clearAllHistory, removeHistoryItem, saveCropResultToHistory,
        cropCurrentResult, openCurrentResultInNewWindow, openSeedInNewWindow,
        analyzeSeedImage, onVirtualTryOnFile, clearVirtualTryOn, extractClothingForTryOn, openTryOnImageInNewWindow
    };
})();
window.AiImage = AiImage;
