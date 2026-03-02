/* HK (Hotkey) + hkKey -> js/core/hotkey.js. 의존: el, App, ED, US, TM, FS, FP, PW, STATS, Translator, Scholar, AiPPT, AppLock, EdCommands, EZ, FM, GH, ins 등 */

/* ═══════════════════════════════════════════════════════════
   HOTKEY ENGINE
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   HK — 단축키 목록 매니저 (편집 가능)
═══════════════════════════════════════════════════════════ */
const HK = (() => {
    const STORAGE_KEY = 'mdpro-hotkeys-v2';

    /* ── action → 실제 함수 매핑 ───────────────────────────────
       handleKey()가 HK.getDispatch()를 통해 이 테이블을 참조하여
       동적으로 디스패치한다. 키 수정 시 rebuild()가 재빌드한다.  */
    const ACTION_MAP = {
        'view.split':       () => App.setViewCycle('split'),
        'view.editor':      () => App.setViewCycle('editor'),
        'view.preview':     () => App.setViewCycle('preview'),
        'ed.h1':            () => ED.h(1),
        'ed.h2':            () => ED.h(2),
        'ed.h3':            () => ED.h(3),
        'ed.pageBreak':     () => ED.pageBreak(),
        'ed.lineBreak':     () => ED.lineBreak(),
        'ed.bold':          () => ED.bold(),
        'ed.italic':        () => ED.italic(),
        'ed.bquote':        () => ED.bquote(),
        'ed.inlineCode':    () => ED.inlineCode(),
        'ed.codeBlock':     () => ED.codeBlockDirect(),
        'ed.table':         () => ED.table(),
        'ed.tableRow':      () => ED.tableRow(),
        'ed.tableCol':      () => ED.tableCol(),
        'ed.mergeH':        () => ED.mergeH(),
        'ed.mergeV':        () => ED.mergeV(),
        'ed.footnote':      () => ED.footnote(),
        'ed.alignLeft':     () => ED.align('left'),
        'ed.alignCenter':   () => ED.align('center'),
        'ed.alignRight':    () => ED.align('right'),
        'ed.moveUp':        () => ED.moveLine(-1),
        'ed.moveDown':      () => ED.moveLine(1),
        'ed.dupLine':       () => ED.dupLine(),
        'ed.undo':          () => US.undo(),
        'ed.redo':          () => US.redo(),
        'fs.inc':           () => FS.inc(),
        'fs.dec':           () => FS.dec(),
        'app.stats':        () => STATS.show(),
        'app.translator':   () => Translator.show(),
        'app.fmtPanel':     () => FP.show(),
        'app.previewWin':   () => PW.open(),
        'app.previewPPT':   () => PW.openSlide(),
        'app.researchMode': () => App.toggleRM(),
        'app.cite':         () => App.showCite(),
        'app.scholar':      () => Scholar.show(),
        'app.aiPPT':        () => AiPPT.open(),
        'app.save':         () => App.smartSave(),
        'app.find':         () => App.toggleFind(),
        'app.toggleMultiEditBar': () => App.toggleMultiEditBar(),
        'app.multiEditApply': () => { if (el('multi-edit-bar') && el('multi-edit-bar').classList.contains('vis')) App.multiEditApply(); },
        'app.hotkeys':      () => App.showHK(),
        'app.toggleSidebar': () => App.toggleSidebar(),
        'app.themeDark':    () => App.setTheme('dark'),
        'app.themeLight':   () => App.setTheme('light'),
        'app.themeToggle':  () => App.toggleTheme(),
        'app.wordWrap':     () => App.toggleWordWrap(),
        'app.lock':         () => { if (typeof AppLock !== 'undefined') AppLock.lockNow(); },
        'app.nbsp':         () => { const ed = el('editor'), s = ed.selectionStart; ins(ed, s, ed.selectionEnd, '&nbsp;'); US.snap(); },
        'tab.new':          () => TM.newTab(),
        'tab.open':         () => TM.openFile(),
        'tab.saveAll':      () => TM.saveAll(),
        'tab.close':        () => { const t = TM.getActive(); if (t) TM.closeTab(t.id); },
        'tab.print':        () => App.printDoc(),
        'edit.deleteLine':  () => App.deleteLine(),
        'ed.strikethrough': () => EdCommands.strikethrough(),
        'ed.underline':     () => EdCommands.underline(),
        'ed.sup':           () => EdCommands.sup(),
        'ed.sub':           () => EdCommands.sub(),
        'ed.highlight':     () => EdCommands.highlight(),
        'ed.hr':            () => EdCommands.hr(),
        'ed.ul':            () => EdCommands.ul(),
        'ed.ol':            () => EdCommands.ol(),
        'ed.textToList':    () => { ED.textToList(); },
        'ed.textToNumberedList': () => { ED.textToNumberedList(); },
        'ed.task':          () => EdCommands.task(),
        'ed.link':          () => EdCommands.link(),
        'ed.image':         () => EdCommands.image(),
        'ed.indentIn':      () => EdCommands.indentIn(),
        'ed.indentOut':     () => EdCommands.indentOut(),
        'ed.textToTable':   () => ED.textToTable(),
        'ed.mdTableToHtml': () => ED.mdTableToHtml(),
        'tab.prev':         () => { const tabs=TM.getAll(); const i=tabs.findIndex(t=>t.id===TM.getActive()?.id); if(i>0) TM.switchTab(tabs[i-1].id); },
        'tab.next':         () => { const tabs=TM.getAll(); const i=tabs.findIndex(t=>t.id===TM.getActive()?.id); if(i<tabs.length-1) TM.switchTab(tabs[i+1].id); },
        'app.insertDate':   () => App.insertDate(),
        'app.makeImageLink': () => App.makeImageLink(),
        'app.openSelectionAsLink': () => App.openSelectionAsLink(),
        'app.insertAuthorInfo': () => { if (typeof AuthorInfo !== 'undefined') AuthorInfo.insertIntoEditor(); },
        'app.charMap':      () => CharMap.show(),
        'app.syncToggle':   () => SS.toggle(),
        'app.ghCommit':     () => { const t=TM.getActive(); if(t&&t.ghPath) App._openGHSaveModal(t); },
        'app.pullGH':       () => FM.pullFromGitHub(),
        'app.pushGH':       () => FM.syncToGitHub(),
        'edit.deleteLine':  () => App.deleteLine(),
    };

    /* ── 기본 단축키 데이터 ─────────────────────────────────────
       keys : 표시용 문자열 (사용자가 편집)
       action: ACTION_MAP 키 — 이 값이 실제 동작을 결정한다.     */
    const DEFAULT_DATA = [
        {
            section: '문서 구조', items: [
                { desc: 'H1', keys: 'Ctrl + Alt + 1', action: 'ed.h1' },
                { desc: 'H2', keys: 'Ctrl + Alt + 2', action: 'ed.h2' },
                { desc: 'H3', keys: 'Ctrl + Alt + 3', action: 'ed.h3' },
                { desc: '페이지 나누기', keys: 'Ctrl + Enter', action: 'ed.pageBreak' },
                { desc: '줄바꿈 (<br>)', keys: 'Ctrl + Shift + Enter', action: 'ed.lineBreak' },
            ]
        },
        {
            section: '표 편집', items: [
                { desc: '텍스트 → 표 변환', keys: 'Alt + 7', action: 'ed.textToTable' },
                { desc: '마크다운 표 → HTML 표', keys: 'Alt + H', action: 'ed.mdTableToHtml' },
                { desc: '표 삽입', keys: 'Alt + 8', action: 'ed.table' },
                { desc: '행 추가', keys: 'Alt + 9', action: 'ed.tableRow' },
                { desc: '열 추가', keys: 'Alt + 0', action: 'ed.tableCol' },
                { desc: '가로 병합 (colspan)', keys: 'Alt + Shift + H', action: 'ed.mergeH' },
                { desc: '세로 병합 (rowspan)', keys: 'Alt + Shift + V', action: 'ed.mergeV' },
                { desc: 'HTML 표 들여쓰기 정돈', keys: 'Tidy 버튼', action: '' },
            ]
        },
        {
            section: '텍스트 서식', items: [
                { desc: 'Smart Bold', keys: 'Ctrl + B', action: 'ed.bold' },
                { desc: '기울임꼴', keys: 'Ctrl + I', action: 'ed.italic' },
                { desc: '인용구', keys: 'Ctrl + .', action: 'ed.bquote' },
                { desc: '인라인 코드 `code`', keys: 'Alt + V', action: 'ed.inlineCode' },
                { desc: '코드 직접 삽입 (마지막 언어)', keys: 'Alt + C', action: 'ed.codeBlock' },
                { desc: '글자 크기 키우기', keys: 'Shift + Alt + .', action: 'fs.inc' },
                { desc: '글자 크기 줄이기', keys: 'Shift + Alt + ,', action: 'fs.dec' },
            ]
        },
        {
            section: '레이아웃 / 정렬', items: [
                { desc: '왼쪽 정렬', keys: 'Shift + Alt + L', action: 'ed.alignLeft' },
                { desc: '가운데 정렬', keys: 'Shift + Alt + C', action: 'ed.alignCenter' },
                { desc: '오른쪽 정렬', keys: 'Shift + Alt + R', action: 'ed.alignRight' },
                { desc: '사이드바 토글 (열기/닫기)', keys: 'Alt + W', action: 'app.toggleSidebar' },
                { desc: 'Split 보기', keys: 'Alt + 1', action: 'view.split' },
                { desc: '에디터만', keys: 'Alt + 2', action: 'view.editor' },
                { desc: '미리보기만', keys: 'Alt + 3', action: 'view.preview' },
                { desc: '전체 다크/라이트 토글', keys: 'Alt + 4', action: 'app.themeToggle' },
                { desc: 'Word Wrap (줄바꿈) 토글', keys: 'Alt + Z', action: 'app.wordWrap' },
            ]
        },
        {
            section: '편집', items: [
                { desc: '줄 위로 이동', keys: 'Alt + ArrowUp', action: 'ed.moveUp' },
                { desc: '줄 아래로 이동', keys: 'Alt + ArrowDown', action: 'ed.moveDown' },
                { desc: '줄 / 선택 복제', keys: 'Shift + Alt + ArrowDown', action: 'ed.dupLine' },
                { desc: '실행 취소', keys: 'Ctrl + Z', action: 'ed.undo' },
                { desc: '다시 실행', keys: 'Ctrl + Shift + Z', action: 'ed.redo' },
                { desc: '다시 실행 (대체)', keys: 'Ctrl + Y', action: 'ed.redo' },
                { desc: '현재 줄 삭제', keys: 'Alt + Y', action: 'edit.deleteLine' },
            ]
        },
        {
            section: '삽입 / 도구', items: [
                { desc: '오늘 날짜 삽입', keys: 'Shift + Alt + D', action: 'app.insertDate' },
                { desc: '작성자 정보 삽입', keys: 'Shift + Alt + A', action: 'app.insertAuthorInfo' },
                { desc: '이미지 링크 만들기', keys: 'Alt + I', action: 'app.makeImageLink' },
                { desc: '선택 텍스트 → 하이퍼링크 새창', keys: 'Shift + Alt + I', action: 'app.openSelectionAsLink' },
                { desc: '인용 삽입', keys: 'Ctrl + Shift + C', action: 'app.cite' },
                { desc: '각주 삽입', keys: 'Shift + Alt + N', action: 'ed.footnote' },
                { desc: 'APA 통계 삽입', keys: 'Shift + Alt + 9', action: 'app.stats' },
                { desc: '번역기', keys: 'Shift + Alt + G', action: 'app.translator' },
                { desc: '서식 패널 (크기·색·형광펜)', keys: 'Alt + L', action: 'app.fmtPanel' },
                { desc: '새창 미리보기', keys: 'Ctrl + Shift + P', action: 'app.previewWin' },
                { desc: '슬라이드 모드로 새창 열기', keys: 'Ctrl + Shift + T', action: 'app.previewPPT' },
                { desc: '저장 다이얼로그', keys: 'Ctrl + S', action: 'app.save' },
                { desc: '찾기 / 바꾸기', keys: 'Ctrl + H', action: 'app.find' },
                { desc: '다중선택 편집 (선택 시 메뉴 열기)', keys: 'Ctrl + Alt + K', action: 'app.toggleMultiEditBar' },
                { desc: '다중선택 편집 (선택→바꾸기 전체 적용)', keys: 'Ctrl + Enter', action: 'app.multiEditApply' },
                { desc: 'Research Mode', keys: 'Ctrl + Shift + R', action: 'app.researchMode' },
                { desc: 'Scholar 검색', keys: 'Ctrl + Shift + G', action: 'app.scholar' },
                { desc: 'AI PPT (ScholarSlide)', keys: 'Ctrl + Shift + L', action: 'app.aiPPT' },
                { desc: '단축키 목록 & 설정', keys: 'Alt + /', action: 'app.hotkeys' },
                { desc: '문자표 (특수문자)', keys: 'Ctrl + Q', action: 'app.charMap' },
                { desc: '에디터-PV 스크롤 동기화', keys: 'Shift + Alt + M', action: 'app.syncToggle' },
                { desc: '앱 잠금', keys: 'Ctrl + G', action: 'app.lock' },
                { desc: '새 탭', keys: 'Ctrl + N', action: 'tab.new' },
                { desc: '파일 열기', keys: 'Ctrl + O', action: 'tab.open' },
                { desc: '탭 닫기', keys: 'Ctrl + W', action: 'tab.close' },
                { desc: '전체 저장', keys: 'Ctrl + Shift + S', action: 'tab.saveAll' },
                { desc: '인쇄', keys: 'Ctrl + P', action: 'tab.print' },
                { desc: '줄바꿈 공백 (&nbsp;)', keys: 'Ctrl + Shift + Space', action: 'app.nbsp' },
            ]
        },
        {
            section: '추가 서식', items: [
                { desc: '취소선 (~~)', keys: '', action: 'ed.strikethrough' },
                { desc: '밑줄', keys: '', action: 'ed.underline' },
                { desc: '위첨자', keys: '', action: 'ed.sup' },
                { desc: '아래첨자', keys: '', action: 'ed.sub' },
                { desc: '형광펜 (==)', keys: '', action: 'ed.highlight' },
                { desc: '수평선', keys: '', action: 'ed.hr' },
                { desc: '순서없는 목록', keys: '', action: 'ed.ul' },
                { desc: '텍스트→목록 항목 (•)', keys: 'Alt + 5', action: 'ed.textToList' },
                { desc: '텍스트→숫자 목록 (1. 2. 3.)', keys: 'Alt + 6', action: 'ed.textToNumberedList' },
                { desc: '체크리스트', keys: '', action: 'ed.task' },
                { desc: '링크 삽입', keys: '', action: 'ed.link' },
                { desc: '이미지 삽입', keys: '', action: 'ed.image' },
                { desc: '들여쓰기', keys: '', action: 'ed.indentIn' },
                { desc: '내어쓰기', keys: '', action: 'ed.indentOut' },
            ]
        },
        {
            section: '탭 이동', items: [
                { desc: '이전 탭', keys: '', action: 'tab.prev' },
                { desc: '다음 탭', keys: '', action: 'tab.next' },
            ]
        },
        {
            section: 'GitHub 연동', items: [
                { desc: 'GitHub 커밋 (현재 파일)', keys: '', action: 'app.ghCommit' },
                { desc: 'GitHub Pull', keys: '', action: 'app.pullGH' },
                { desc: 'GitHub Push', keys: '', action: 'app.pushGH' },
            ]
        },
    ];

    let data = [];
    let editMode = false;

    function load() {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                const parsed = JSON.parse(saved);
                // action 필드가 없는 구버전(v1) 데이터 → 기본값으로 초기화
                const hasAction = parsed.some(g => g.items && g.items.some(i => i.action !== undefined));
                data = hasAction ? parsed : JSON.parse(JSON.stringify(DEFAULT_DATA));
            } else {
                data = JSON.parse(JSON.stringify(DEFAULT_DATA));
            }
        } catch (e) {
            data = JSON.parse(JSON.stringify(DEFAULT_DATA));
        }
    }

    function save() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) { }
    }

    /* ── keys 표시 문자열 → hkKey() 정규화 형식 변환 ───────────
       'Ctrl + Shift + Z'  →  'C+S+Z'
       'Alt + ArrowUp'     →  'A+ArrowUp'
       'Tidy 버튼' 같은 비키 항목 → null                         */
    function parseHotkey(keysStr) {
        if (!keysStr) return null;
        // modifier 없이 '버튼', 'Tidy' 등 단순 텍스트는 키 항목이 아님
        const hasMod = /ctrl|shift|alt|cmd|option/i.test(keysStr);
        if (!hasMod && !keysStr.includes('+')) return null;
        const tokens = keysStr.split('+').map(s => s.trim()).filter(Boolean);
        if (tokens.length === 0) return null;
        const mods = [];
        let mainKey = null;
        for (const t of tokens) {
            const lo = t.toLowerCase();
            if (lo === 'ctrl' || lo === 'cmd') mods.push('C');
            else if (lo === 'shift') mods.push('S');
            else if (lo === 'alt' || lo === 'option') mods.push('A');
            else mainKey = t;
        }
        if (!mainKey) return null;
        // 특수 키 이름은 그대로, 단일 문자는 대문자로
        if (mainKey.length === 1) mainKey = mainKey.toUpperCase();
        // 'Space' → 공백 문자로 (hkKey는 e.key=' '를 ' '.toUpperCase()=' '로 반환)
        if (mainKey.toLowerCase() === 'space') mainKey = ' ';
        return [...mods, mainKey].join('+');
    }

    /* ── Shift 조합 시 브라우저 e.key 변환 대응 ────────────────
       Shift+9 → e.key='(' 이므로 canonical 'S+A+9' 외에
       'S+A+(' 도 함께 등록해야 매칭된다.                         */
    const SHIFT_CHAR = {
        '1':'!','2':'@','3':'#','4':'$','5':'%',
        '6':'^','7':'&','8':'*','9':'(','0':')',
        '-':'_','=':'+',
        ';':':',',':'<','.':'>','/':'?',
    };

    function getMatchKeys(keysStr) {
        const base = parseHotkey(keysStr);
        if (!base) return [];
        const results = [base];
        // Shift가 포함된 단일 문자 키: 실제 e.key 변환값도 추가
        const tokens = keysStr.split('+').map(s => s.trim());
        const hasShift = tokens.some(t => t.toLowerCase() === 'shift');
        const mainKey = tokens.find(t => !['ctrl','cmd','shift','alt','option'].includes(t.toLowerCase()));
        if (hasShift && mainKey && mainKey.length === 1) {
            const shifted = SHIFT_CHAR[mainKey.toLowerCase()];
            if (shifted) {
                // 'C+S+9' → 'C+S+(' 형태로 교체
                const alt = base.slice(0, base.lastIndexOf('+') + 1) + shifted.toUpperCase();
                if (alt !== base) results.push(alt);
            }
        }
        return results;
    }

    /* ── dispatch 테이블 빌드 ───────────────────────────────────
       data를 순회하며 { hkKey형식: fn } 매핑을 생성한다.
       save() 또는 resetDefault() 후에 반드시 호출해야 한다.      */
    let _dispatch = {};

    function rebuild() {
        _dispatch = {};
        data.forEach(group => {
            (group.items || []).forEach(item => {
                if (!item.action || !item.keys) return;
                const fn = ACTION_MAP[item.action];
                if (!fn) return;
                getMatchKeys(item.keys).forEach(k => { _dispatch[k] = fn; });
            });
        });
        /* 역방향 맵 갱신 (handleKey의 getActionId에서 사용) */
        _fnToId = new Map();
        Object.entries(ACTION_MAP).forEach(([id, fn]) => { _fnToId.set(fn, id); });
    }

    function getDispatch() { return _dispatch; }
    function getActionMap() { return ACTION_MAP; }

    /* fn → actionId 역방향 조회 캐시 (rebuild() 내에서 갱신) */
    let _fnToId = new Map();

    function getActionId(fn) { return _fnToId.get(fn) || null; }

    function render() {
        const wrap = el('hk-list-wrap');
        wrap.innerHTML = '';
        const actionKeys = Object.keys(ACTION_MAP);
        data.forEach((group, gi) => {
            // 섹션 헤더
            const sec = document.createElement('div');
            sec.className = 'hk-s';
            sec.style.cssText = 'display:flex;align-items:center;gap:6px';
            if (editMode) {
                const inp = document.createElement('input');
                inp.className = 'hk-editable desc';
                inp.style.cssText = 'font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--ac);flex:1';
                inp.value = group.section;
                inp.oninput = () => { data[gi].section = inp.value; };
                const delSec = document.createElement('button');
                delSec.className = 'hk-del-btn';
                delSec.title = '섹션 삭제';
                delSec.textContent = '✕';
                delSec.onclick = () => { data.splice(gi, 1); render(); };
                sec.appendChild(inp);
                sec.appendChild(delSec);
            } else {
                sec.textContent = group.section;
            }
            wrap.appendChild(sec);

            // 그리드
            const grid = document.createElement('div');
            grid.className = editMode ? 'hk-grid edit-mode' : 'hk-grid';
            grid.style.marginBottom = '4px';

            group.items.forEach((item, ii) => {
                const row = document.createElement('div');
                if (editMode) {
                    row.className = 'hk-item-edit';

                    const descInp = document.createElement('input');
                    descInp.className = 'hk-editable desc';
                    descInp.value = item.desc;
                    descInp.oninput = () => { data[gi].items[ii].desc = descInp.value; };

                    const keysInp = document.createElement('input');
                    keysInp.className = 'hk-editable keys';
                    keysInp.value = item.keys;
                    keysInp.placeholder = 'Ctrl + Shift + X';
                    keysInp.title = '예: Ctrl + Z  |  Shift + Alt + ArrowDown  |  Alt + 9';
                    keysInp.oninput = () => { data[gi].items[ii].keys = keysInp.value; };

                    // action 드롭다운 — 핵심: 어떤 기능과 연결할지 선택
                    const actSel = document.createElement('select');
                    actSel.className = 'hk-editable';
                    actSel.style.cssText = 'font-size:10px;padding:2px 4px;background:var(--bg4);color:var(--tx2);border:1px solid var(--bd);border-radius:3px;min-width:90px;max-width:150px;flex-shrink:0';
                    actSel.title = '이 키에 연결할 기능';
                    const emptyOpt = document.createElement('option');
                    emptyOpt.value = '';
                    emptyOpt.textContent = '— 표시용 —';
                    actSel.appendChild(emptyOpt);
                    actionKeys.forEach(ak => {
                        const opt = document.createElement('option');
                        opt.value = ak;
                        opt.textContent = ak;
                        opt.selected = item.action === ak;
                        actSel.appendChild(opt);
                    });
                    actSel.onchange = () => { data[gi].items[ii].action = actSel.value; };

                    const del = document.createElement('button');
                    del.className = 'hk-del-btn';
                    del.title = '행 삭제';
                    del.innerHTML = '🗑';
                    del.onclick = () => { data[gi].items.splice(ii, 1); render(); };

                    row.appendChild(descInp);
                    row.appendChild(keysInp);
                    row.appendChild(actSel);
                    row.appendChild(del);
                } else {
                    row.className = 'hk-item';
                    const keys = item.keys.split('+').map(k => k.trim()).filter(Boolean);
                    row.innerHTML = `<span class="hk-desc">${item.desc}</span><div class="hk-keys">${keys.map(k => `<kbd>${k}</kbd>`).join('')}</div>`;
                }
                grid.appendChild(row);
            });

            // 편집 모드: 이 섹션에 행 추가 버튼
            if (editMode) {
                const addRow = document.createElement('div');
                addRow.style.cssText = 'padding:2px 6px;';
                const addBtn = document.createElement('button');
                addBtn.className = 'btn btn-g btn-sm';
                addBtn.style.cssText = 'font-size:10px;padding:2px 7px;width:100%;opacity:.7';
                addBtn.textContent = '+ 이 섹션에 행 추가';
                addBtn.onclick = () => { data[gi].items.push({ desc: '새 항목', keys: '', action: '' }); render(); };
                addRow.appendChild(addBtn);
                grid.appendChild(addRow);
            }

            wrap.appendChild(grid);
        });

        // 편집 모드: 섹션 추가 버튼
        if (editMode) {
            const addSec = document.createElement('button');
            addSec.className = 'btn btn-g btn-sm';
            addSec.style.cssText = 'width:100%;margin-top:6px;font-size:11px';
            addSec.textContent = '＋ 섹션 추가';
            addSec.onclick = () => { data.push({ section: '새 섹션', items: [{ desc: '항목', keys: '', action: '' }] }); render(); };
            wrap.appendChild(addSec);
        }
    }

    return {
        open() {
            try {
                load(); rebuild(); editMode = false;
                const editBtn = el('hk-edit-btn');
                if (editBtn) { editBtn.textContent = '✎ 편집'; editBtn.classList.remove('btn-p'); editBtn.classList.add('btn-g'); }
                const editHint = el('hk-edit-hint');
                if (editHint) editHint.style.display = 'none';
                const editActions = el('hk-edit-actions');
                if (editActions) editActions.style.display = 'none';
                /* 로그인 후에만 설정(비밀번호 변경 / 앱 잠금) 표시 */
                const settingsRow = document.getElementById('hk-settings-row');
                const btnChangePw = document.getElementById('hk-btn-change-pw');
                const btnLock = document.getElementById('hk-btn-lock');
                if (settingsRow && typeof AppLock !== 'undefined') {
                    const unlocked = AppLock.isUnlocked();
                    const hasLock = AppLock.hasLock();
                    settingsRow.style.display = 'flex';
                    if (btnChangePw) {
                        if (hasLock) {
                            btnChangePw.textContent = '🔑 비밀번호 변경';
                            btnChangePw.onclick = function() { App.hideHK(); AppLock.showChangePw(); };
                            btnChangePw.style.display = '';
                        } else {
                            btnChangePw.textContent = '🔑 비밀번호 설정';
                            btnChangePw.onclick = function() { App.hideHK(); AppLock.showSetPw(); };
                            btnChangePw.style.display = '';
                        }
                    }
                    if (btnLock) {
                        btnLock.style.display = hasLock ? '' : 'none';
                    }
                    const autolockInp = document.getElementById('hk-autolock-input');
                    if (autolockInp) autolockInp.value = AppLock.getAutoLockMinutes();
                } else if (settingsRow) {
                    settingsRow.style.display = 'none';
                }
                /* 다중선택 span방식 (설정, 기본 ON) - 로그인 여부와 무관하게 표시 */
                const spanChk = document.getElementById('hk-me-spanmethod');
                if (spanChk) {
                    spanChk.checked = localStorage.getItem('mdpro_me_spanmethod') !== '0';
                    spanChk.onchange = function() { try { localStorage.setItem('mdpro_me_spanmethod', spanChk.checked ? '1' : '0'); } catch (e) {} };
                }
                /* 에디터 현재 줄 하이라이트 행 항상 표시 */
                const lineHighlightRow = document.getElementById('hk-line-highlight-row');
                if (lineHighlightRow) lineHighlightRow.style.display = 'flex';
                render();
                el('hk-overlay').classList.add('vis');
                try { if (typeof EditorLineHighlight !== 'undefined') { EditorLineHighlight.updateUI(); EditorLineHighlight.loadToPanel(); } } catch (e) { console.warn('EditorLineHighlight:', e); }
                try { if (typeof EditorAutoPair !== 'undefined') EditorAutoPair.updateUI(); } catch (e) { console.warn('EditorAutoPair.updateUI:', e); }
                try { if (typeof AuthorInfo !== 'undefined') AuthorInfo.loadToPanel(); } catch (e) { console.warn('AuthorInfo.loadToPanel:', e); }
                try { if (typeof ImgLink !== 'undefined') ImgLink.loadToPanel(); } catch (e) { console.warn('ImgLink.loadToPanel:', e); }
                try { if (typeof FindHighlight !== 'undefined') FindHighlight.loadToPanel(); } catch (e) { console.warn('FindHighlight.loadToPanel:', e); }
                try { if (typeof EditorSelection !== 'undefined') EditorSelection.loadToPanel(); } catch (e) { console.warn('EditorSelection.loadToPanel:', e); }
            } catch (err) {
                console.error('HK.open:', err);
                const ov = el('hk-overlay');
                if (ov) ov.classList.add('vis');
            }
        },
        close() {
            el('hk-overlay').classList.remove('vis');
            editMode = false;
        },
        toggleEdit() {
            editMode = !editMode;
            const btn = el('hk-edit-btn');
            if (editMode) {
                btn.textContent = '✓ 완료';
                btn.classList.add('btn-p');
                btn.classList.remove('btn-g');
                el('hk-edit-hint').style.display = 'block';
                el('hk-edit-actions').style.display = 'flex';
            } else {
                // 완료 → 저장 + dispatch 재빌드
                save(); rebuild();
                btn.textContent = '✎ 편집';
                btn.classList.remove('btn-p');
                btn.classList.add('btn-g');
                el('hk-edit-hint').style.display = 'none';
                el('hk-edit-actions').style.display = 'none';
            }
            render();
        },
        addRow() {
            if (data.length === 0) data.push({ section: '기타', items: [] });
            data[data.length - 1].items.push({ desc: '새 항목', keys: '', action: '' });
            render();
        },
        saveEdit() {
            save(); rebuild(); editMode = false;
            el('hk-edit-btn').textContent = '✎ 편집';
            el('hk-edit-btn').classList.remove('btn-p');
            el('hk-edit-btn').classList.add('btn-g');
            el('hk-edit-hint').style.display = 'none';
            el('hk-edit-actions').style.display = 'none';
            render();
        },
        resetDefault() {
            if (!confirm('단축키 목록을 기본값으로 되돌리겠습니까?')) return;
            data = JSON.parse(JSON.stringify(DEFAULT_DATA));
            save(); rebuild(); render();
        },
        /* 앱 초기화 시 App.init()에서 호출 — open() 없이도 dispatch 테이블 구성 */
        _initDispatch() {
            load();
            rebuild();
        },
        getDispatch,
        getActionMap,
        getActionId,
    };
})();


function hkKey(e) {
    const mac = navigator.platform.toUpperCase().includes('MAC');
    const ctrl = mac ? e.metaKey : e.ctrlKey;
    const parts = [];
    if (ctrl) parts.push('C');
    if (e.shiftKey) parts.push('S');
    if (e.altKey) parts.push('A');
    /* Alt+숫자 시 e.key가 %^ 등으로 오므로, Digit 키는 e.code로 숫자 사용 */
    let mainKey = e.key;
    if (e.altKey && e.code && /^Digit\d$/.test(e.code)) mainKey = e.code.replace('Digit', '');
    /* Shift+Ctrl+숫자 시 e.key가 !@# 등으로 오므로, Digit는 e.code로 숫자 사용 (전체 테마 단축키 등 매칭) */
    else if ((ctrl || e.ctrlKey || e.metaKey) && e.shiftKey && e.code && /^Digit\d$/.test(e.code)) mainKey = e.code.replace('Digit', '');
    else if (e.key && e.key.length === 1) mainKey = e.key.toUpperCase();
    parts.push(mainKey);
    return parts.join('+');
}
