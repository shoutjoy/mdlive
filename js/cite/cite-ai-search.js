/* CiteAISearch — cite-modal 전용 AI 참고문헌 검색 (Gemini) */
const CiteAISearch = (() => {
    async function callGemini(prompt) {
        const key = typeof AiApiKey !== 'undefined' ? AiApiKey.get() : '';
        if (!key) throw new Error('AI API 키를 설정에서 입력·저장해 주세요.');
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(key)}`;
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.3, maxOutputTokens: 4096 }
            }),
            signal: AbortSignal.timeout(60000)
        });
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error?.message || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const parts = d.candidates?.[0]?.content?.parts || [];
        return parts.map(p => (p.text || '').trim()).filter(Boolean).join('\n').trim();
    }

    function run() {
        const inp = document.getElementById('cite-ai-prompt');
        const status = document.getElementById('cite-ai-status');
        const resultBox = document.getElementById('cite-ai-result');
        const placeholder = document.getElementById('cite-ai-placeholder');
        if (!inp || !resultBox) return;
        const q = (inp.value || '').trim();
        if (!q) {
            if (status) status.textContent = '검색할 주제를 입력하세요.';
            return;
        }
        const prompt = `List 5 to 10 academic references in APA 7 format for the following topic. Output only the reference list, one reference per line. No numbering, no extra explanation.\n\nTopic: ${q}`;
        if (status) status.textContent = '🔄 AI 검색 중...';
        if (placeholder) placeholder.style.display = 'none';
        resultBox.innerHTML = '<div class="cite-empty" style="padding:16px">⏳ 생성 중...</div>';
        callGemini(prompt).then(text => {
            const lines = text.split(/\n/).map(s => s.trim()).filter(s => s.length > 5);
            if (status) status.textContent = lines.length ? `✅ ${lines.length}건 제안` : '제안된 참고문헌이 없습니다.';
            if (lines.length === 0) {
                resultBox.innerHTML = '<div class="cite-empty" id="cite-ai-placeholder">제안된 참고문헌이 없습니다. 프롬프트를 바꿔 다시 시도하세요.</div>';
                return;
            }
            resultBox.innerHTML = lines.map((line, i) => {
                const escaped = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                return `<div class="ref-card" style="margin-bottom:8px">
  <div class="ref-card-apa" style="font-size:12px">${escaped}</div>
  <div class="ref-card-btns" style="margin-top:4px">
    <button type="button" class="btn btn-p btn-sm" onclick="CiteAISearch.addLine(${i})">+ 참고문헌에 추가</button>
  </div>
</div>`;
            }).join('');
            resultBox._lines = lines;
        }).catch(e => {
            if (status) status.textContent = `❌ ${e.message}`;
            resultBox.innerHTML = `<div class="cite-empty" id="cite-ai-placeholder">오류: ${e.message}</div>`;
        });
    }

    function addLine(i) {
        const box = document.getElementById('cite-ai-result');
        const line = box._lines?.[i];
        if (!line || typeof CM === 'undefined') return;
        CM.addRaw(line);
        const btns = box.querySelectorAll('.ref-card')[i]?.querySelectorAll('button');
        if (btns?.[0]) { btns[0].textContent = '✔ 추가됨'; btns[0].disabled = true; btns[0].style.opacity = '.6'; }
    }

    return { run, addLine };
})();
