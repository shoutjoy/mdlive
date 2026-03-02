/* Scholar — 학술 검색 (Google Scholar, RISS, KCI, DBpia 등), mdRender 의존 */
/* ═══════════════════════════════════════════════════════════
   ACADEMIC SEARCH (Google Scholar, RISS, KCI, DBpia, IEEE 등)
═══════════════════════════════════════════════════════════ */
const Scholar = (() => {
    const RK = 'mdpro_scholar_recent';
    let recent = [];
    let currentTab = 'google';

    const APA_GUIDE_MD = `# 📘 APA 7판 참고문헌 작성 가이드 (학술연구자용 정리본)

본 문서는 학술논문 작성 시 참고문헌을 **APA 7판(American Psychological Association, 7th ed.)** 기준에 따라 정확하게 작성하기 위한 규칙을 정리한 연구자용 가이드이다.
한국어 논문과 영어 논문이 혼재된 경우에도 동일한 원칙이 적용되며, 언어에 따른 세부 차이만 존재한다.

---

# 1️⃣ APA 7판의 기본 원칙

APA 7판 참고문헌 작성의 핵심 원칙은 다음과 같다.

1. 모든 참고문헌은 저자 성 기준 알파벳순으로 배열한다.
2. 한글 논문과 영문 논문을 구분하지 않고 동일한 규칙을 적용한다.
3. 학술지명과 권(volume)은 반드시 이탤릭체로 표기한다.
4. 논문 제목은 문장형(sentence case)으로 작성한다.
5. DOI가 있는 경우 반드시 https://doi.org/ 형식으로 표기한다.
6. 각 참고문헌 사이에는 한 줄 공백을 둔다.

---

# 2️⃣ 학술지 논문의 기본 형식

## 🔹 기본 구조

저자. (연도). 논문 제목. *학술지명, 권*(호), 페이지. DOI

---

# 3️⃣ 저자 표기 규칙

## ① 한국어 저자

- 성과 이름을 그대로 작성한다.
- 이니셜로 변환하지 않는다.
- 쉼표로 저자를 구분한다.

예시
전희원, 김영화.

---

## ② 영어 저자

- 성, 이름 이니셜 순으로 표기한다.
- 이름은 이니셜로 축약한다.
- 저자가 20명 이하이면 모두 표기한다.
- 21명 이상이면 19명까지 표기 후 … 마지막 저자를 표기한다.

예시
Henrich, W. L., Smith, J. A., & Brown, R. T.

---

# 4️⃣ 연도 표기

- 반드시 괄호 안에 작성한다.
- 괄호 뒤에는 마침표를 찍는다.

형식
(2007).

---

# 5️⃣ 논문 제목 작성 규칙

## ① 한국어 논문 제목

- 원문 그대로 작성한다.
- 따옴표를 사용하지 않는다.
- 별도 대소문자 변경을 하지 않는다.

## ② 영어 논문 제목

- 문장형(sentence case) 적용
- 첫 단어와 고유명사만 대문자로 작성한다.
- 나머지는 소문자로 작성한다.

예시
Analgesics and the kidney: Summary and recommendations to the scientific advisory board of the National Kidney Foundation.

---

# 6️⃣ 학술지명 및 권·호 표기

## 🔹 이탤릭 적용 대상

- 학술지명
- 권(volume)

## 🔹 일반체 유지

- 호(issue)
- 페이지

예시
*American Journal of Kidney Diseases, 27*(1), 162–165.

또는

*관광연구, 22*(2), 285–307.

---

# 7️⃣ 페이지 표기

- 시작 페이지와 끝 페이지 사이에는 en dash(–) 사용
- 하이픈(-)이 아니라 en dash 사용

예시
285–307.

---

# 8️⃣ DOI 표기

- 반드시 URL 형식 사용
- doi: 또는 DOI: 사용하지 않음
- http:// 대신 https:// 사용

형식
https://doi.org/10.xxxxx

---

# 9️⃣ 한국어 논문과 영어 논문의 차이 요약

| 구분 | 한국어 논문 | 영어 논문 |
|------|-------------|-----------|
| 저자명 | 한글 원형 유지 | 성 + 이니셜 |
| 제목 | 원문 유지 | sentence case |
| 학술지명 | 원문 유지 | Title Case |
| 이탤릭 | 적용 | 적용 |
| DOI | 동일 | 동일 |

---

# 🔟 예시 정리

전희원, 김영화. (2007). 호텔종사원의 집단응집력과 자긍심이 조직몰입, 직무만족 및 직무성과에 미치는 영향. *관광연구, 22*(2), 285–307.

HEE, K. S., Lim, R. J., 이은희. (2019). 중소병원 간호사의 간호근무환경과 조직몰입 간의 관계: 수간호사 신뢰의 조절효과. *Asia-Pacific Journal of Multimedia Services Convergent with Art, Humanities and Sociology, 9*(9), 437–449. https://doi.org/10.35873/ajmahs.2019.9.9.038

Henrich, W. L., et al. (1996). Analgesics and the kidney: Summary and recommendations to the scientific advisory board of the National Kidney Foundation from an ad hoc committee of the National Kidney Foundation. *American Journal of Kidney Diseases, 27*(1), 162–165. https://doi.org/10.1016/s0272-6386(96)90046-3

---

# 📌 최종 정리

APA 7판은 언어에 따라 다른 형식을 요구하는 것이 아니다.
동일한 구조 안에서 저자 표기 방식과 제목 대소문자 규칙만 언어 특성에 맞게 달라질 뿐이다.
한국어 학술지 역시 반드시 이탤릭을 적용하는 것이 원칙이다.

---

본 문서는 연구자용 참고문헌 작성 표준 안내서로 활용할 수 있다.
`;

    /** localStorage에서 최근 검색어 목록(RK) 복원. 없거나 오류 시 빈 배열 */
    function load() { try { recent = JSON.parse(localStorage.getItem(RK) || '[]') } catch (e) { recent = [] } }

    /** 현재 선택된 탭(Google/Yonsei/RISS/KCI/DBpia/IEEE/ScienceDirect)에 맞춰 UI 전환 및 해당 검색 패널 포커스 */
    function tab(name) {
        currentTab = name;
        document.querySelectorAll('#scholar-modal .tab-row .tab').forEach(t => t.classList.remove('active'));
        const tabEl = document.querySelector(`#scholar-modal .tab-row .tab:nth-child(${['google','yonsei','sciencedirect','riss','kci','dbpia','ieee'].indexOf(name)+1})`);
        if (tabEl) tabEl.classList.add('active');
        document.querySelectorAll('#scholar-modal .tp').forEach(p => p.classList.remove('active'));
        const panel = document.getElementById('scholar-panel-' + name);
        if (panel) panel.classList.add('active');
        setTimeout(() => {
            const inp = document.querySelector('#scholar-panel-' + name + ' input[type=text]');
            if (inp) inp.focus();
        }, 50);
    }

    /** Scholar 검색 모달 표시, 최근 검색어 렌더, 현재 탭으로 초기화 후 검색 입력란에 포커스 */
    function show() {
        load(); renderRecent(); el('scholar-modal').classList.add('vis');
        tab(currentTab);
        setTimeout(() => {
            const inp = document.querySelector('#scholar-panel-' + currentTab + ' input[type=text]');
            if (inp) inp.focus();
        }, 80);
    }

    /** 현재 탭에 해당하는 검색어 입력란의 값을 반환 (Google/Yonsei/RISS 등 탭별 입력소스) */
    function getQ() {
        switch (currentTab) {
            case 'google': return el('scholar-q')?.value?.trim() || '';
            case 'yonsei': return el('scholar-yonsei-q')?.value?.trim() || '';
            case 'riss': return el('scholar-riss-q')?.value?.trim() || '';
            case 'dbpia': return el('scholar-dbpia-q')?.value?.trim() || '';
            case 'ieee': return el('scholar-ieee-q')?.value?.trim() || '';
            case 'sciencedirect': return el('scholar-sd-qs')?.value?.trim() || el('scholar-sd-authors')?.value?.trim() || el('scholar-sd-pub')?.value?.trim() || '';
            case 'kci': return el('scholar-kci-main')?.value?.trim() || el('scholar-kci-author')?.value?.trim() || el('scholar-kci-journal')?.value?.trim() || el('scholar-kci-publisher')?.value?.trim() || '';
            default: return '';
        }
    }

    /** 현재 탭의 검색 조건으로 외부 검색 사이트 URL 생성 (Google Scholar, RISS, KCI, DBpia, IEEE 등). KCI는 blob URL(자동제출 폼) 반환 */
    function buildUrl() {
        const enc = (s) => encodeURIComponent((s || '').trim());
        switch (currentTab) {
            case 'google': {
                const q = el('scholar-q').value.trim();
                if (!q) return null;
                const params = new URLSearchParams();
                params.set('q', q);
                params.set('hl', (el('scholar-lang')?.value || 'ko') === 'ko' ? 'ko' : 'en');
                const year = el('scholar-year')?.value;
                if (year) params.set('as_ylo', year);
                if (el('scholar-review')?.checked) params.set('as_rr', '1');
                return `https://scholar.google.com/scholar?${params.toString()}`;
            }
            case 'yonsei': {
                const q = el('scholar-yonsei-q').value.trim();
                if (!q) return null;
                return `https://library.yonsei.ac.kr/searchTotal?q=${enc(q)}`;
            }
            case 'sciencedirect': {
                const qs = el('scholar-sd-qs').value.trim();
                const authors = el('scholar-sd-authors').value.trim();
                const pub = el('scholar-sd-pub').value.trim();
                if (!qs && !authors && !pub) return null;
                const params = new URLSearchParams();
                if (qs) params.set('qs', qs);
                if (authors) params.set('authors', authors);
                if (pub) params.set('pub', pub);
                return `https://www.sciencedirect.com/search?${params.toString()}`;
            }
            case 'riss': {
                const q = el('scholar-riss-q').value.trim();
                if (!q) return null;
                return `https://www.riss.kr/search/Search.do?query=${enc(q)}`;
            }
            case 'kci': {
                const main = el('scholar-kci-main').value.trim();
                const author = el('scholar-kci-author').value.trim();
                const journal = el('scholar-kci-journal').value.trim();
                const publisher = el('scholar-kci-publisher').value.trim();
                if (!main && !author && !journal && !publisher) return null;
                // KCI input: #mainSearchKeyword, #search_top ul li:nth-child(2)=저자, (3)=간행지, (4)=발행기관
                // 폼 자동제출로 main.kci에 전달 (mainSearchKeyword 등 파라미터명 시도)
                const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>KCI 검색</title></head><body>
<form id="kciForm" action="https://www.kci.go.kr/kciportal/main.kci" method="GET">
<input type="hidden" name="mainSearchKeyword" value="${esc(main)}">
<input type="hidden" name="searchAuthor" value="${esc(author)}">
<input type="hidden" name="searchJournal" value="${esc(journal)}">
<input type="hidden" name="searchPublisher" value="${esc(publisher)}">
</form>
<script>document.getElementById('kciForm').submit();</script>
<p style="font-family:sans-serif;padding:20px">KCI 검색 페이지로 이동 중...</p>
</body></html>`;
                const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
                return URL.createObjectURL(blob);
            }
            case 'dbpia': {
                const q = el('scholar-dbpia-q').value.trim();
                if (!q) return null;
                return `https://www.dbpia.co.kr/search/topSearch?query=${enc(q)}`;
            }
            case 'ieee': {
                const q = el('scholar-ieee-q').value.trim();
                if (!q) return null;
                return `https://ieeexplore.ieee.org/search/searchresult.jsp?queryText=${enc(q)}`;
            }
            default: return null;
        }
    }

    /** buildUrl()로 만든 URL로 새 창을 열어 검색 실행. Google Scholar일 때는 검색어를 최근 검색 목록에 추가 */
    function search() {
        const url = buildUrl();
        if (!url) {
            const inp = document.querySelector('#scholar-panel-' + currentTab + ' input[type=text]');
            if (inp) inp.focus();
            App._toast?.('검색어를 입력하세요.');
            return;
        }
        if (currentTab === 'kci') {
            const main = el('scholar-kci-main')?.value?.trim() || '';
            if (main) navigator.clipboard.writeText(main).catch(() => {});
            window.open(url, 'scholar_search_' + currentTab, 'width=1100,height=800,left=100,top=80,resizable=yes,scrollbars=yes');
            if (url.startsWith('blob:')) setTimeout(() => URL.revokeObjectURL(url), 5000);
        } else {
            window.open(url, 'scholar_search_' + currentTab, 'width=1100,height=800,left=100,top=80,resizable=yes,scrollbars=yes');
        }

        const q = getQ();
        if (q && currentTab === 'google') {
            recent = recent.filter(r => r !== q); recent.unshift(q); recent = recent.slice(0, 8);
            try { localStorage.setItem(RK, JSON.stringify(recent)) } catch (e) { }
            renderRecent();
        }
    }

    /** 최근 검색어 목록(recent)을 #scholar-recent 영역에 칩 형태로 렌더. 클릭 시 useRecent 호출, ✕ 시 removeRecent */
    function renderRecent() {
        const wrap = el('scholar-recent-wrap');
        const div = el('scholar-recent');
        if (!wrap || !div) return;
        wrap.style.display = 'block';
        if (!recent.length) {
            div.innerHTML = '<span style="font-size:11px;color:var(--tx3)">최근 검색어가 없습니다. Google Scholar 등에서 검색하면 여기에 표시됩니다.</span>';
            return;
        }
        const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const escapeJs = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
        div.innerHTML = recent.map((r, i) => {
            const esc = escapeJs(r);
            const safe = escapeHtml(r);
            return `<span style="display:inline-flex;align-items:center;gap:3px;background:var(--bg5);border:1px solid var(--bd);border-radius:var(--r);padding:2px 6px 2px 8px;font-size:11px;color:var(--tx2)"><span style="cursor:pointer" onclick="Scholar.useRecent('${esc}')">🕐 ${safe}</span><button type="button" onclick="event.stopPropagation();Scholar.removeRecent(${i})" style="background:none;border:none;cursor:pointer;padding:0 2px;font-size:12px;color:var(--tx3);line-height:1" title="이 검색어 지우기">✕</button></span>`;
        }).join('');
    }

    /** 최근 검색어 목록에서 지정 인덱스 항목 제거 후 localStorage 저장 및 renderRecent 갱신 */
    function removeRecent(index) {
        if (index < 0 || index >= recent.length) return;
        recent.splice(index, 1);
        try { localStorage.setItem(RK, JSON.stringify(recent)) } catch (e) { }
        renderRecent();
    }

    /** 최근 검색어(q)를 모든 탭의 검색 입력란에 동일하게 넣고 search() 실행 (한 번에 동일 검색어로 검색) */
    function useRecent(q) {
        el('scholar-q').value = q;
        el('scholar-yonsei-q').value = q;
        el('scholar-riss-q').value = q;
        el('scholar-dbpia-q').value = q;
        el('scholar-ieee-q').value = q;
        el('scholar-sd-qs').value = q;
        el('scholar-kci-main').value = q;
        search();
    }

    /** 모든 검색 입력란 및 최근 검색 목록 초기화, localStorage의 최근 검색어 삭제 후 현재 탭 입력란에 포커스 */
    function clear() {
        el('scholar-q').value = '';
        el('scholar-yonsei-q').value = '';
        el('scholar-riss-q').value = '';
        el('scholar-dbpia-q').value = '';
        el('scholar-ieee-q').value = '';
        el('scholar-sd-qs').value = '';
        el('scholar-sd-authors').value = '';
        el('scholar-sd-pub').value = '';
        el('scholar-kci-main').value = '';
        el('scholar-kci-author').value = '';
        el('scholar-kci-journal').value = '';
        el('scholar-kci-publisher').value = '';
        recent = [];
        try { localStorage.removeItem(RK) } catch (e) { }
        renderRecent();
        const inp = document.querySelector('#scholar-panel-' + currentTab + ' input[type=text]');
        if (inp) inp.focus();
    }

    /** APA 7판 참고문헌 작성 가이드(APA_GUIDE_MD)를 마크다운 렌더 후 새 창에 표시. 확대/축소 버튼 제공 */
    function openApaGuide() {
        let html;
        try {
            html = typeof mdRender === 'function' ? mdRender(APA_GUIDE_MD, true) : (typeof marked !== 'undefined' ? marked.parse(APA_GUIDE_MD) : APA_GUIDE_MD.replace(/\n/g, '<br>'));
        } catch (e) {
            html = '<p style="color:var(--er)">' + (e.message || '렌더 오류') + '</p>';
        }
        html = (html || '').replace(/<\/script>/gi, '<\\/script>');
        const base = window.location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
        const w = window.open('', '_blank', 'width=800,height=700,scrollbars=yes,resizable=yes');
        if (!w) { alert('팝업이 차단되었을 수 있습니다.'); return; }
        w.document.write(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>APA 7판 참고문헌 작성 가이드</title><base href="' + base + '"><link rel="stylesheet" href="style.css"></head>' +
            '<body style="margin:0;background:var(--bg1);display:flex;flex-direction:column;min-height:100vh;font-family:inherit">' +
            '<div style="flex-shrink:0;padding:8px 12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;background:var(--bg3);flex-wrap:wrap">' +
            '<button type="button" onclick="var p=document.getElementById(\'apa-guide-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.min(24,s+2)+\'px\';var L=document.getElementById(\'apa-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">확대</button>' +
            '<button type="button" onclick="var p=document.getElementById(\'apa-guide-content\');var s=parseInt(p.style.fontSize,10)||13;p.style.fontSize=Math.max(10,s-2)+\'px\';var L=document.getElementById(\'apa-zoom-label\');if(L)L.textContent=Math.round((parseInt(p.style.fontSize,10)/13)*100)+\'%\'" style="padding:4px 10px;cursor:pointer;border:1px solid var(--bd);border-radius:4px;background:var(--bg2);color:var(--tx);font-size:12px">축소</button>' +
            '<span id="apa-zoom-label" style="font-size:11px;color:var(--tx3);min-width:40px">100%</span>' +
            '</div>' +
            '<div id="apa-guide-content" style="flex:1;min-height:0;overflow:auto;padding:20px;font-size:13px;line-height:1.7">' +
            '<div class="preview-page" style="max-width:720px;margin:0 auto">' + html + '</div></div></body></html>'
        );
        w.document.close();
    }

    return { show, search, useRecent, removeRecent, clear, tab, openApaGuide };
})();