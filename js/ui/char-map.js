/* CharMap - 문자표(특수문자 삽입) -> js/ui/char-map.js. 의존: el, US, TM, App */

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