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
                try { if (typeof EditorLineHighlight !== 'undefined') EditorLineHighlight.updateUI(); } catch (e) { console.warn('EditorLineHighlight.updateUI:', e); }
                try { if (typeof EditorAutoPair !== 'undefined') EditorAutoPair.updateUI(); } catch (e) { console.warn('EditorAutoPair.updateUI:', e); }
                try { if (typeof AuthorInfo !== 'undefined') AuthorInfo.loadToPanel(); } catch (e) { console.warn('AuthorInfo.loadToPanel:', e); }
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

function handleKey(e) {
    const edi = el('editor');
    const inEd = document.activeElement === edi;
    const k = hkKey(e);

    /* ── 괄호·따옴표 자동쌍 & 선택 감싸기: ( [ " ' (설정 ON일 때만) ── */
    if (inEd && typeof EditorAutoPair !== 'undefined' && EditorAutoPair.handleKey(e)) return;

    /* ── Ctrl+H: 찾기/바꾸기 (브라우저 히스토리 등에 빼앗기지 않도록 우선 처리) ── */
    if ((e.ctrlKey || e.metaKey) && e.key && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        e.stopPropagation();
        if (typeof App !== 'undefined' && App.toggleFind) App.toggleFind();
        return;
    }

    /* ── Alt+4: 전체 다크/라이트 토글 (항상 동작) ── */
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.code === 'Digit4' || e.key === '4')) {
        e.preventDefault();
        if (typeof App !== 'undefined' && App.toggleTheme) App.toggleTheme();
        return;
    }

    /* ── Ctrl+9: 에디터 축소, Ctrl+0: 에디터 확대 ── */
    if ((e.ctrlKey || e.metaKey) && e.key === '9') { e.preventDefault(); EZ.dec(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key === '0') { e.preventDefault(); EZ.inc(); return; }

    /* ── Tab / Shift+Tab: 에디터 들여쓰기 (표 안이면 셀 이동 우선) ──────
       표 안 → tabInTable()이 처리 (셀 이동)
       표 밖 + 선택 없음:
           Tab        → 커서 위치에 공백 2칸 삽입
           Shift+Tab  → 줄 앞 공백 2칸 제거
       표 밖 + 다중 줄 선택:
           Tab        → 선택된 각 줄 앞에 공백 2칸 추가
           Shift+Tab  → 선택된 각 줄 앞 공백 2칸 제거
    ─────────────────────────────────────────────────────────────── */
    if (e.key === 'Tab' && inEd) {
        if (ED.tabInTable(edi, e)) return;   // 표 안: 셀 이동
        e.preventDefault();
        const val = edi.value;
        const ss = edi.selectionStart;
        const se = edi.selectionEnd;
        const INDENT = '  ';                  // 공백 2칸

        if (ss === se) {
            /* 선택 없음: 커서 위치에 공백 삽입 or 줄 앞 제거 */
            if (e.shiftKey) {
                const ls = val.lastIndexOf('\n', ss - 1) + 1;
                if (val.slice(ls, ls + INDENT.length) === INDENT) {
                    edi.value = val.slice(0, ls) + val.slice(ls + INDENT.length);
                    edi.setSelectionRange(Math.max(ls, ss - INDENT.length), Math.max(ls, ss - INDENT.length));
                }
            } else {
                edi.value = val.slice(0, ss) + INDENT + val.slice(se);
                edi.setSelectionRange(ss + INDENT.length, ss + INDENT.length);
            }
        } else {
            /* 다중 줄 선택: 각 줄 일괄 indent / dedent */
            const ls = val.lastIndexOf('\n', ss - 1) + 1;   // 선택 첫 줄 시작
            const block = val.slice(ls, se);
            let newBlock;
            if (e.shiftKey) {
                newBlock = block.replace(/^  /gm, '');
            } else {
                newBlock = block.replace(/^/gm, INDENT);
            }
            const delta = newBlock.length - block.length;
            edi.value = val.slice(0, ls) + newBlock + val.slice(se);
            edi.setSelectionRange(ls, se + delta);
        }
        US.snap(); TM.markDirty(); App.render();
        return;
    }

    /* ── Enter: 표 행 자동 추가 비활성화 (행 추가는 툴바 +행 버튼 사용) ── */
    // if (e.key === 'Enter' && inEd) { if (ED.enterInTable(edi, e)) return; }

    /* ── Alt+Enter: 현재 줄 목록 수준 유지하며 줄바꿈 ──────────────────────
       - "  - 내용"   → "\n  - "  (같은 indent + bullet)
       - "  1. 내용"  → "\n  2. " (같은 indent + 다음 번호)
       - "  - [ ] "   → "\n  - [ ] " (체크박스)
       - prefix 없음  → "\n" 일반 줄바꿈
    ─────────────────────────────────────────────────────────────────────── */
    if (e.altKey && e.key === 'Enter' && inEd) {
        e.preventDefault();
        const { text } = getCL(edi);
        const pos = edi.selectionStart;
        const m = text.match(/^(\s*)([-*+]\s+(?:\[[ xX]\]\s+)?|(\d+)\.\s+)/);
        let insertion;
        if (m) {
            const indent = m[1];
            const num    = m[3];
            if (num !== undefined) {
                insertion = '\n' + indent + (parseInt(num, 10) + 1) + '. ';
            } else if (/\[[ xX]\]/.test(m[2])) {
                insertion = '\n' + indent + '- [ ] ';
            } else {
                insertion = '\n' + indent + m[2];
            }
        } else {
            insertion = '\n';
        }
        ins(edi, pos, edi.selectionEnd, insertion);
        return;
    }

    /* ── Alt+5 / Alt+6: 목록 변환 (Windows 등에서 e.key가 %^ 로 오므로 e.code로만 판별) ── */
    if (inEd && e.altKey && !e.ctrlKey && !e.metaKey &&
        (e.code === 'Digit5' || e.code === 'Digit6')) {
        e.preventDefault();
        e.stopPropagation();
        if (e.code === 'Digit5') ED.textToList();
        else ED.textToNumberedList();
        return;
    }

    /* ── Alt+I: 이미지 링크 만들기 (선택 URL → HTML img) ── */
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
        if (typeof App !== 'undefined' && App.makeImageLink) App.makeImageLink();
        return;
    }

    const dispatch = HK.getDispatch();
    const fn = dispatch[k];
    if (!fn) return;

    /* ── action prefix로 전역/에디터 전용 분기 ─────────────────
       view.* / app.* / fs.*  → 전역: 에디터 포커스와 무관하게 실행
       ed.*                   → 에디터 전용: 에디터에 포커스가 있을 때만 실행
       이 구분 덕분에 Alt+3으로 preview 전환 후에도 Alt+1,2가 정상 동작함 */
    const actionId = HK.getActionId(fn);
    const isGlobal = actionId && !actionId.startsWith('ed.');

    if (isGlobal) {
        e.preventDefault();
        fn();
    } else if (inEd) {
        e.preventDefault();
        fn();
    }
    /* ed.* 이고 에디터 포커스가 없으면: preventDefault 없이 return → 브라우저 기본 동작 유지 */
}


/* ═══════════════════════════════════════════════════════════
   TOOLTIP
═══════════════════════════════════════════════════════════ */
function initTooltip() {
    const tip = el('tooltip'); let t;
    document.addEventListener('mouseover', e => { const target = e.target.closest('[data-tooltip]'); if (!target) return; clearTimeout(t); t = setTimeout(() => { const key = target.dataset.key; tip.innerHTML = target.dataset.tooltip + (key ? ` <span class="tt-key">${key}</span>` : ''); tip.classList.add('vis'); let x = e.clientX + 12, y = e.clientY + 16; if (x + 260 > window.innerWidth) x = e.clientX - 260; if (y + 40 > window.innerHeight) y = e.clientY - 40; tip.style.left = x + 'px'; tip.style.top = y + 'px' }, 300) });
    document.addEventListener('mouseout', () => { clearTimeout(t); tip.classList.remove('vis') });
}

/* ═══════════════════════════════════════════════════════════
   MAIN APP
═══════════════════════════════════════════════════════════ */
const App = {
    rm: false, rt: null, colorMode: 'text', capType: 'table',

    init() {
        TM.init(); CM.load(); initTooltip(); SS.init(); FS.update(); LN.init(); EZ.init();
        if (typeof EditorLineHighlight !== 'undefined') EditorLineHighlight.init();
        if (typeof EditorAutoPair !== 'undefined') EditorAutoPair.init();
        SB.init();  /* 저장된 소스 탭(로컬/GitHub) 복원 */
        /* 테마 복원: 전체 / 에디터 / PV 각각 */
        try {
            const globalTheme = localStorage.getItem('mdpro_theme');
            if (globalTheme === 'light') document.documentElement.dataset.theme = 'light';
            const edTheme = localStorage.getItem('mdpro_editor_theme');
            const ep = document.getElementById('editor-pane');
            if (ep && edTheme) ep.dataset.editorTheme = edTheme;
            if (typeof PV !== 'undefined' && PV.initTheme) PV.initTheme();
        } catch (e) {}
        App._updateEditorThemeBtn();
        /* FM.restore는 DOMContentLoaded에서 별도 호출 */
        /* HK 초기화: 앱 시작 시 load + rebuild 해야 핫키가 작동함 */
        try { HK._initDispatch(); } catch(e) {}
        /* Ctrl+H: 찾기/바꾸기 — 캡처 단계에서 선점해 브라우저(히스토리 등)에 빼앗기지 않도록 */
        CoreEvents.init();
        // Set default view button state
        const splitBtn = el('vm-split'); if (splitBtn) splitBtn.classList.add('active');
        const edi = el('editor');
        el('tmpl-grid').innerHTML = TMPLS.map((t, i) => `<div class="tmpl-card" onclick="App.insertTmpl(${i})"><h4>${t.icon} ${t.name}</h4><p>${t.desc}</p></div>`).join('');

        if (!edi.value) edi.value = this.sample();
        this.render(); US.snap();

/* ── Split Resizer 초기화 ──────────────────────────────── */
(function initSplitResizer() {
    const resizer    = document.getElementById('split-resizer');
    const edPane     = document.getElementById('editor-pane');
    const pvPane     = document.getElementById('preview-pane');
    const wrap       = document.getElementById('editor-wrap');
    if (!resizer || !edPane || !pvPane || !wrap) return;

    /* 저장된 비율 복원 */
    const saved = parseFloat(localStorage.getItem('mdpro_split_ratio') || '0.5');
    function applyRatio(r) {
        r = Math.max(0.15, Math.min(0.85, r));
        edPane.style.flex  = 'none';
        pvPane.style.flex  = 'none';
        edPane.style.width = (r * 100).toFixed(2) + '%';
        pvPane.style.width = ((1 - r) * 100).toFixed(2) + '%';
    }
    applyRatio(saved);

    /* 숨김 패널일 때는 flex 리셋 */
    const resetFlex = () => {
        if (edPane.classList.contains('hidden')) { pvPane.style.flex = '1'; pvPane.style.width = ''; }
        else if (pvPane.classList.contains('hidden')) { edPane.style.flex = '1'; edPane.style.width = ''; }
    };

    let startX = 0, startEdW = 0, totalW = 0, dragging = false;

    function startDrag(clientX) {
        if (edPane.classList.contains('hidden') || pvPane.classList.contains('hidden')) return;
        dragging  = true;
        startX    = clientX;
        startEdW  = edPane.getBoundingClientRect().width;
        totalW    = wrap.getBoundingClientRect().width - resizer.offsetWidth;
        document.body.classList.add('resizing');
        resizer.classList.add('dragging');
    }
    function moveDrag(clientX) {
        if (!dragging) return;
        const dx    = clientX - startX;
        const newW  = Math.max(120, Math.min(totalW - 120, startEdW + dx));
        const ratio = newW / totalW;
        applyRatio(ratio);
    }
    function endDrag() {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove('resizing');
        resizer.classList.remove('dragging');
        const r = edPane.getBoundingClientRect().width / (wrap.getBoundingClientRect().width - resizer.offsetWidth);
        localStorage.setItem('mdpro_split_ratio', r.toFixed(4));
    }

    resizer.addEventListener('mousedown', e => {
        if (e.button !== 0) return;
        e.preventDefault();
        startDrag(e.clientX);
    });

    document.addEventListener('mousemove', e => {
        if (!dragging) return;
        moveDrag(e.clientX);
    });

    document.addEventListener('mouseup', e => {
        endDrag();
    });

    /* 터치: 모바일에서 에디터·미리보기 구분선 조절 (리사이저에서만 시작, UI 내에서만 동작) */
    resizer.addEventListener('touchstart', e => {
        if (e.touches.length !== 1) return;
        e.preventDefault();
        startDrag(e.touches[0].clientX);
    }, { passive: false });

    document.addEventListener('touchmove', e => {
        if (!dragging) return;
        if (e.touches.length !== 1) return;
        e.preventDefault();
        moveDrag(e.touches[0].clientX);
    }, { passive: false });

    document.addEventListener('touchend', endDrag);
    document.addEventListener('touchcancel', endDrag);

    /* 더블클릭: 50:50 리셋 */
    resizer.addEventListener('dblclick', () => {
        applyRatio(0.5);
        localStorage.setItem('mdpro_split_ratio', '0.5');
    });

    /* setView 호출 시 flex 리셋 필요 */
    const origSetView = App.setView.bind(App);
    App.setView = function(m) {
        origSetView(m);
        edPane.style.flex = ''; edPane.style.width = '';
        pvPane.style.flex = ''; pvPane.style.width = '';
        if (m === 'split') {
            const r = parseFloat(localStorage.getItem('mdpro_split_ratio') || '0.5');
            applyRatio(r);
        }
        resetFlex();
    };
})();
    },

    render() {
        const edi = el('editor'); const md = edi.value, title = el('doc-title').value;
        clearTimeout(this.rt);
        this.rt = setTimeout(() => { Render.run(md, title); }, 120);
        this.updCursor();
    },

    updCursor() { CursorUI.updCursor(); },
    updFmtBtns() { CursorUI.updFmtBtns(); },
    showErrs(errs) { const ec = el('error-count'), sep = el('ec-sep'), list = el('ep-list'), panel = el('error-panel'); if (!errs.length) { ec.textContent = ''; sep.style.display = 'none'; panel.classList.remove('vis'); return } ec.textContent = `⚠ ${errs.length}개 오류`; sep.style.display = 'block'; list.innerHTML = errs.map(e => `<div class="error-item">${e}</div>`).join('') },
    toggleErr() { el('error-panel').classList.toggle('vis') }, closeErr() { el('error-panel').classList.remove('vis') },
    toggleSidebar() { el('app').classList.toggle('ns') },
    setView(m) { el('editor-pane').classList.toggle('hidden', m === 'preview'); el('preview-pane').classList.toggle('hidden', m === 'editor') },
    setViewCycle(m) {
        this.setView(m);
        ['split', 'editor', 'preview'].forEach(v => { const b = el('vm-' + v); if (b) b.classList.toggle('active', v === m) });
    },
    toggleTheme() {
        const isLight = document.documentElement.dataset.theme === 'light';
        const nextLight = !isLight;
        document.documentElement.dataset.theme = nextLight ? 'light' : '';
        const ep = document.getElementById('editor-pane');
        if (ep) ep.dataset.editorTheme = nextLight ? 'light' : 'dark';
        if (typeof PV !== 'undefined' && PV.setDark) PV.setDark(!nextLight);
        try {
            localStorage.setItem('mdpro_theme', nextLight ? 'light' : 'dark');
            localStorage.setItem('mdpro_editor_theme', nextLight ? 'light' : 'dark');
        } catch (e) {}
        App._updateEditorThemeBtn();
    },
    setTheme(theme) {
        const isLight = theme === 'light';
        document.documentElement.dataset.theme = isLight ? 'light' : '';
        const ep = document.getElementById('editor-pane');
        if (ep) ep.dataset.editorTheme = isLight ? 'light' : 'dark';
        if (typeof PV !== 'undefined' && PV.setDark) PV.setDark(!isLight);
        try {
            localStorage.setItem('mdpro_theme', isLight ? 'light' : 'dark');
            localStorage.setItem('mdpro_editor_theme', isLight ? 'light' : 'dark');
        } catch (e) {}
        App._updateEditorThemeBtn();
    },
    toggleEditorTheme() {
        const ep = document.getElementById('editor-pane');
        if (!ep) return;
        const cur = ep.dataset.editorTheme || (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
        const next = cur === 'light' ? 'dark' : 'light';
        ep.dataset.editorTheme = next;
        try { localStorage.setItem('mdpro_editor_theme', next); } catch (e) {}
        App._updateEditorThemeBtn();
    },
    _updateEditorThemeBtn() {
        const ep = document.getElementById('editor-pane');
        const btn = document.getElementById('ed-theme-btn');
        if (!btn) return;
        const isLight = ep ? (ep.dataset.editorTheme === 'light') : (document.documentElement.dataset.theme === 'light');
        btn.textContent = isLight ? '◐' : '◑';
        btn.title = isLight ? '에디터 라이트 (클릭 시 다크)' : '에디터 다크 (클릭 시 라이트)';
    },
    toggleRM() { this.rm = !this.rm; el('rm-badge').classList.toggle('vis', this.rm); el('mode-ind').textContent = this.rm ? 'RESEARCH' : 'NORMAL'; PR.rm = this.rm; PW.setRM(this.rm); this.render() },
    showHK() { HK.open() }, hideHK() { HK.close() },
    showCode() { el('code-modal').classList.add('vis') },
    showLink() { el('link-modal').classList.add('vis'); setTimeout(() => el('link-text').focus(), 50) },
    showImg() {
        // reset drop zone
        el('img-drop-text').textContent = '🖼 클릭 또는 드래그';
        el('img-drop-text').style.color = '';
        el('img-dropzone').style.borderColor = ''; el('img-dropzone').style.background = '';
        if (typeof AiImage !== 'undefined') AiImage.switchTab('insert');
        _showImgpv(el('img-url') ? el('img-url').value.trim() : '');
        _bindImgUrlToImgpv();
        _bindImgCodeToPreview();
        el('image-modal').classList.add('vis'); setTimeout(() => el('img-alt').focus(), 50);
    },
    makeImageLink() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        let url = (ed.value.slice(s, e) || '').trim();
        if (!url) {
            alert('URL을 선택한 뒤 Alt+I를 누르거나 🖼 링크 버튼을 누르세요.');
            return;
        }
        if (!/^https?:\/\//i.test(url) && !/^data:image\//i.test(url)) {
            alert('선택한 내용이 URL이 아닙니다.\nhttps://... 또는 data:image/... 형식을 선택해 주세요.');
            return;
        }
        const isImageUrl = /^data:image\//i.test(url) || /\.(jpe?g|png|gif|webp|svg|bmp|ico)(\?.*)?$/i.test(url);
        let tag;
        if (isImageUrl) {
            const width = '500';
            const esc = url.replace(/"/g, '&quot;');
            tag = '<img src="' + esc + '" border="0" width="' + width + '">';
        } else {
            const label = prompt('링크 표시 텍스트 (비우면 URL 그대로 표시):', '');
            if (label === null) return;
            const text = label.trim() !== '' ? label.trim() : url;
            const escHref = url.replace(/"/g, '&quot;').replace(/&/g, '&amp;');
            const escText = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            tag = '<a href="' + escHref + '">' + escText + '</a>';
        }
        if (typeof ED !== 'undefined' && typeof ED.ins === 'function') {
            ED.ins(ed, s, e, tag);
        } else {
            ed.setRangeText(tag, s, e, 'end');
        }
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    openSelectionAsLink() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const text = (ed.value.slice(s, e) || '').trim();
        if (!text) {
            alert('링크로 넣을 URL 또는 텍스트를 선택한 뒤 Shift+Alt+I를 누르거나 🔗 새창 버튼을 누르세요.');
            return;
        }
        let href, label;
        if (/^https?:\/\//i.test(text)) {
            href = text;
            const input = prompt('링크 표시 텍스트 (비우면 URL 그대로 표시):', '');
            if (input === null) return;
            label = input.trim() !== '' ? input.trim() : text;
        } else {
            const urlInput = prompt('링크 URL:', text);
            if (urlInput === null) return;
            href = (urlInput || '').trim() || text;
            const textInput = prompt('링크 표시 텍스트 (비우면 URL 표시):', text);
            if (textInput === null) return;
            label = (textInput || '').trim() !== '' ? textInput.trim() : href;
        }
        const escHref = href.replace(/"/g, '&quot;').replace(/&/g, '&amp;');
        const escLabel = label.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const tag = '<a href="' + escHref + '" target="_blank" rel="noopener">' + escLabel + '</a>';
        if (typeof ED !== 'undefined' && typeof ED.ins === 'function') {
            ED.ins(ed, s, e, tag);
        } else {
            ed.setRangeText(tag, s, e, 'end');
        }
        ed.focus();
        if (typeof US !== 'undefined' && US.snap) US.snap();
        if (typeof TM !== 'undefined' && TM.markDirty) TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    showCite() { CM.open(); el('cite-modal').classList.add('vis') },
    showStats() { STATS.show() },
    /* ── 스마트 저장 (Ctrl+S) ──────────────────────────── */
    async smartSave() {
        const tab = TM.getActive();
        if (!tab) return;
        if (tab.ghPath) { App._openGHSaveModal(tab); return; }
        /* 파일핸들 있으면 바로 덮어쓰기 */
        if (tab._fileHandle) {
            try {
                const perm = await tab._fileHandle.queryPermission({ mode: 'readwrite' });
                if (perm === 'granted') {
                    await LocalFS.writeToHandle(tab._fileHandle, el('editor').value);
                    TM.markClean(tab.id); TM.renderTabs();
                    App._toast('\u{1F4BE} \uC800\uC7A5\uB428 \u2014 ' + tab.title);
                    return;
                }
            } catch(e) { /* 권한 없으면 폴백 */ }
        }
        App.showSaveDlg();
    },
    showSaveDlg() {
        const tab = TM.getActive();
        if (tab && tab.ghPath) { App._openGHSaveModal(tab); return; }
        const infoEl = el('save-current-info');
        const pathEl = el('save-current-path');
        if (infoEl && pathEl) {
            if (tab && (tab.filePath || tab._fileHandle)) {
                pathEl.textContent = tab.filePath || tab.title;
                infoEl.style.display = '';
            } else { infoEl.style.display = 'none'; }
        }
        el('save-modal').classList.add('vis');
    },
    /* ── GitHub 커밋 (저장 모달 → Git 버튼) ─────────── */
    async saveAndGitCommit() {
        App.hideModal('save-modal');
        const tab = TM.getActive();
        if (!tab) return;
        if (!GH.isConnected()) {
            alert('GitHub\uC774 \uC5F0\uACB0\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.\n\uD83D\uDC19 GitHub \uD0ED \u2192 \uC124\uC815\uC5D0\uC11C \uBA3C\uC800 \uC5F0\uACB0\uD558\uC138\uC694.');
            return;
        }
        if (!tab.ghPath) {
            const ghCfg = GH.cfg;
            const titleHasExt = /\.[a-zA-Z0-9]+$/.test(tab.title || '');
            const fname = (tab.title || 'untitled') + (titleHasExt ? '' : '.md');
            const basePart = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const ghPath = basePart + fname;
            const ok = confirm(`GitHub에 새 파일로 커밋합니다.\n\n경로: ${ghPath}\n\n계속하시겠습니까?`);
            if (!ok) return;
            tab.ghPath   = ghPath;
            tab.ghBranch = ghCfg.branch;
        }
        App._openGHSaveModal(tab);
    },
    showModal(id)  { el(id).classList.add('vis'); },

    /* ── GitHub 저장 모달 열기 ──────────────────────────── */
    _openGHSaveModal(tab) {
        if (!tab) return;

        /* ── 전체 경로 계산 ──────────────────────────────────
           tab.ghPath 가 있으면 그대로 사용,
           없으면 GH basePath + title + .md 로 자동 조합
           ※ tab.title 에 이미 .md 가 있으면 중복 추가 방지  */
        const ghCfg    = GH.cfg || {};
        const basePart = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';

        let fullPath;
        if (tab.ghPath) {
            fullPath = tab.ghPath;
        } else {
            /* title에 확장자가 있으면 그대로, 없으면 .md 추가 */
            const titleHasExt = /\.[a-zA-Z0-9]+$/.test(tab.title || '');
            const fname = (tab.title || 'untitled') + (titleHasExt ? '' : '.md');
            fullPath = basePart + fname;
        }

        /* 파일 경로 입력란 — 전체 경로(폴더/파일명) 자동 채움 + 수정 가능 */
        const pathInput = el('gh-save-file-path');
        if (pathInput) pathInput.value = fullPath;

        /* 파일명 변경 감지 */
        const origPath  = tab.ghPath;
        const origName  = origPath ? origPath.split('/').pop().replace(/\.[^.]+$/, '') : null;
        const curName   = tab.title ? tab.title.replace(/\.[^.]+$/, '') : tab.title; // 확장자 제거 후 비교
        const nameChanged = origName && origName !== curName;

        const notice = el('gh-rename-notice');
        const detail = el('gh-rename-detail');
        if (notice && detail) {
            if (nameChanged) {
                const origExt  = origPath ? '.' + origPath.split('.').pop() : '.md';
                const newPath  = origPath.replace(/[^/]+$/, '') + curName + origExt;
                detail.textContent = `${origPath} → ${newPath}`;
                notice.style.display = '';
                notice.dataset.oldPath = origPath;
                notice.dataset.newPath = newPath;
                if (pathInput) pathInput.value = newPath;
            } else {
                notice.style.display = 'none';
            }
        }

        /* 기본 커밋 메시지 — 전체 경로 기준 */
        const msgInput = el('gh-save-commit-msg');
        if (msgInput) {
            const finalPath = (notice && notice.style.display !== 'none')
                ? notice.dataset.newPath : fullPath;
            msgInput.value = nameChanged
                ? `Rename ${origPath} → ${notice.dataset.newPath}`
                : `Update ${fullPath}`;
        }

        /* 커밋 버튼 레이블 */
        const commitBtn = el('gh-save-commit-btn');
        if (commitBtn) commitBtn.textContent = nameChanged ? '🐙 커밋 (파일명 변경)' : '🐙 GitHub 커밋';

        /* 기기명 자동 삽입 */
        const device = localStorage.getItem('mdpro_device_name');
        if (device && msgInput && !msgInput.value.includes('[device:')) {
            msgInput.value += ` [device:${device}]`;
        }

        el('gh-save-modal').classList.add('vis');
    },

    /* ── GitHub 커밋 실행 ───────────────────────────────── */
    async ghSaveCommit() {
        const tab = TM.getActive();
        if (!tab) return;
        const msg      = el('gh-save-commit-msg').value.trim();
        const notice   = el('gh-rename-notice');

        /* 경로 입력란에서 사용자가 수정했을 수 있으므로 최신값 읽기 */
        const pathInput = el('gh-save-file-path');
        const inputPath = pathInput ? pathInput.value.trim() : null;
        const origPath  = tab.ghPath;
        const pathChanged = inputPath && inputPath !== origPath;

        /* 경로가 변경된 경우 rename 처리, 아니면 nameChanged 기존 로직 유지 */
        const nameChanged = (!pathChanged) && notice && notice.style.display !== 'none';

        App.hideModal('gh-save-modal');

        if (pathChanged && origPath) {
            /* 경로(파일명/폴더) 변경 커밋 */
            const content = el('editor').value;
            try {
                const result = await GH.renameAndCommit(origPath, inputPath, content, msg || `Rename ${origPath} → ${inputPath}`);
                tab.ghPath  = inputPath;
                tab.ghSha   = null;
                TM.markClean(tab.id);
                TM.renderTabs();
                App._toast(`✓ 경로 변경 커밋 완료 #${result.commitSha}`);
            } catch(e) {
                alert(`커밋 실패: ${e.message}`);
            }
        } else if (pathChanged && !origPath) {
            /* 새 파일, 경로 직접 지정 */
            tab.ghPath = inputPath;
            const ghCfg = GH.cfg;
            tab.ghBranch = tab.ghBranch || ghCfg.branch;
            const ok = await GH.saveFile(tab.id, msg || `Add ${inputPath}`);
            if (ok) App._toast('✓ GitHub에 저장됨');
        } else if (nameChanged) {
            /* 파일명 변경 커밋 (기존 rename-notice 방식) */
            const oldPath = notice.dataset.oldPath;
            const newPath = notice.dataset.newPath;
            const content = el('editor').value;
            try {
                const result = await GH.renameAndCommit(oldPath, newPath, content, msg);
                tab.ghPath  = newPath;
                tab.ghSha   = null;
                TM.markClean(tab.id);
                TM.renderTabs();
                App._toast(`✓ 파일명 변경 커밋 완료 #${result.commitSha}`);
            } catch(e) {
                alert(`커밋 실패: ${e.message}`);
            }
        } else {
            /* 일반 커밋 — 경로도 그대로 */
            if (inputPath && !origPath) tab.ghPath = inputPath;
            const ok = await GH.saveFile(tab.id, msg || `Update ${tab.title}`);
            if (ok) App._toast('✓ GitHub에 저장됨');
        }
    },

    /* ── 로컬 저장 (.md 다운로드) ───────────────────────── */
    ghSaveLocal() {
        const tab  = TM.getActive();
        const name = tab ? tab.title : 'document';
        const c    = el('editor').value;
        dlBlob(c, name.replace(/[^a-z0-9가-힣\-_. ]/gi, '_') + '.md', 'text/markdown;charset=utf-8');
        App.hideModal('gh-save-modal');
        App._toast('💾 로컬에 저장됨');
    },

    /* ── GitHub 커밋 + md-viewer Push 동시 실행 ── */
    async ghSaveAndPushViewer() {
        /* 1) 먼저 GitHub 커밋 */
        await App.ghSaveCommit();
        /* 2) 이어서 md-viewer push */
        const tab = TM.getActive();
        if (!tab) return;
        const content = el('editor').value;
        await PVShare.quickPush({ name: tab.title || 'document', content });
    },
    deleteLine() {
        const ed = el('editor');
        if (!ed) return;
        const val = ed.value, pos = ed.selectionStart;
        const s = val.lastIndexOf('\n', pos - 1) + 1;
        let e2 = val.indexOf('\n', pos);
        e2 = (e2 === -1) ? val.length : e2 + 1;
        ed.value = val.slice(0, s) + val.slice(e2);
        ed.selectionStart = ed.selectionEnd = Math.min(s, ed.value.length);
        US.snap(); TM.markDirty(); App.render();
    },
    showCommitHistory() {
        App.showModal('gh-history-modal');
        GH.loadHistory(false);
    },
    /* ── 오늘 날짜 삽입 (Shift+Alt+D): 핫키는 오늘 날짜 직접 삽입 ── */
    insertDate() {
        const ed  = el('editor');
        if (!ed) return;
        const dateStr = formatDateTime(new Date());
        const pos = ed.selectionStart;
        const end = ed.selectionEnd;
        ed.setRangeText(dateStr, pos, end, 'end');
        US.snap(); TM.markDirty(); App.render();
    },
    /* ── 날짜 삽입 모달 (버튼 클릭 시): 달력에서 선택 후 삽입 ── */
    _dateInsertCurrent: null,
    _dateInsertShowTime: false,
    openDatePickerModal() {
        this._dateInsertCurrent = new Date();
        this._dateInsertShowTime = false;
        const chk = document.getElementById('date-insert-show-time');
        if (chk) chk.checked = false;
        this._dateInsertRefresh();
        App.showModal('date-insert-modal');
    },
    toggleDateInsertShowTime() {
        const chk = document.getElementById('date-insert-show-time');
        this._dateInsertShowTime = chk ? chk.checked : !this._dateInsertShowTime;
        this._dateInsertRefresh();
    },
    dateInsertAdjust(unit, delta) {
        const d = this._dateInsertCurrent;
        if (!d) return;
        if (unit === 'year') { d.setFullYear(d.getFullYear() + delta); }
        else if (unit === 'month') { d.setMonth(d.getMonth() + delta); }
        else if (unit === 'day') { d.setDate(d.getDate() + delta); }
        else if (unit === 'hour') { d.setHours(d.getHours() + delta); }
        else if (unit === 'min') { d.setMinutes(d.getMinutes() + delta); }
        this._dateInsertRefresh();
    },
    _dateInsertRefresh() {
        const d = this._dateInsertCurrent;
        if (!d) return;
        const y = document.getElementById('date-insert-year');
        const m = document.getElementById('date-insert-month');
        const day = document.getElementById('date-insert-day');
        const h = document.getElementById('date-insert-hour');
        const min = document.getElementById('date-insert-min');
        const preview = document.getElementById('date-insert-preview');
        const timeRow = document.getElementById('date-insert-time-row');
        const showTime = this._dateInsertShowTime;
        if (timeRow) timeRow.style.display = showTime ? '' : 'none';
        if (y) y.textContent = d.getFullYear();
        if (m) m.textContent = d.getMonth() + 1;
        if (day) day.textContent = d.getDate();
        if (h) h.textContent = d.getHours();
        if (min) min.textContent = String(d.getMinutes()).padStart(2, '0');
        if (preview) preview.textContent = showTime ? formatDateTime(d) : (() => { const w = ['일','월','화','수','목','금','토'][d.getDay()]; return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}(${w})`; })();
    },
    insertDateFromPicker() {
        const ed = el('editor');
        if (!ed) return;
        const d = this._dateInsertCurrent || new Date();
        const dateStr = this._dateInsertShowTime ? formatDateTime(d) : (() => { const w = ['일','월','화','수','목','금','토'][d.getDay()]; return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}(${w})`; })();
        const pos = ed.selectionStart;
        const end = ed.selectionEnd;
        ed.setRangeText(dateStr, pos, end, 'end');
        ed.focus();
        US.snap(); TM.markDirty(); App.render();
        App.hideModal('date-insert-modal');
    },

    _toast(msg, duration) {
        let t = document.getElementById('app-toast');
        if (!t) { t = document.createElement('div'); t.id = 'app-toast'; document.body.appendChild(t); }
        t.style.whiteSpace = 'pre-line';
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(t._tid);
        t._tid = setTimeout(() => t.classList.remove('show'), duration || 2200);
    },
    hideModal(id) {
        if (id === 'image-modal') {
            const box = el('image-modal-box');
            if (box) box.classList.remove('img-modal-maximized');
        }
        if (id === 'cite-modal') {
            const box = document.getElementById('cite-modal-box');
            if (box) box.classList.remove('cite-modal-maximized');
        }
        el(id).classList.remove('vis');
    },
    openColorPicker(m) { ColorPicker.open(m) },
    applyColor() { ColorPicker.apply() },
    showCaption(type) { CAP.show(type) },
    updateCapPreview() { CAP.updatePreview() },
    insertCaption() { CAP.insert() },
    showTmpl() { el('tmpl-modal').classList.add('vis') },
    insertTmpl(i) {
        const t = TMPLS[i];
        if (!confirm(`"${t.name}" 양식을 현재 문서에 추가하시겠습니까?`)) return;
        const edi = el('editor'); edi.value = (edi.value.trim() ? edi.value + '\n\n---\n\n' : '') + t.content;
        this.render(); US.snap(); App.hideModal('tmpl-modal');
    },
    insertSlideTmpl() {
        const style = parseInt(el('slide-tmpl-style').value, 10) || 1;
        const count = Math.max(1, Math.min(50, parseInt(el('slide-tmpl-count').value, 10) || 5));
        const parts = [];
        for (let i = 1; i <= count; i++) {
            const block = `# 제목${i}\n\n---\n\n- 내용`;
            parts.push(i < count ? block + '\n\n<div class="page-break"></div>' : block);
        }
        const content = parts.join('\n\n');
        const edi = el('editor');
        edi.value = (edi.value.trim() ? edi.value + '\n\n' : '') + content;
        PR.setSlideMode(true);
        const btn = document.getElementById('slide-mode-btn');
        if (btn) btn.classList.add('active');
        this.render(); US.snap(); App.hideModal('tmpl-modal');
    },

    toggleFind() {
        const bar = el('find-bar');
        const meBar = el('multi-edit-bar');
        if (meBar && meBar.classList.contains('vis')) meBar.classList.remove('vis');
        bar.classList.toggle('vis');
        if (bar.classList.contains('vis')) {
            const edi = el('editor');
            if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                const sel = edi.value.substring(edi.selectionStart, edi.selectionEnd);
                if (sel) el('fi').value = sel;
            }
            el('fi').focus();
            App._findStart = undefined;
            App.updateFindHighlight();
        } else {
            App.updateFindHighlight(true);
        }
    },

    /** 다중선택 편집 바: 선택 시 에디터에 span 삽입(PV에서 하이라이트), 닫을 때 span 제거 후 마무리 */
    _multiEditSpanStyle: 'background:#ffcc80',
    _multiEditSavedSelection: null,
    _ME_SPANMETHOD_KEY: 'mdpro_me_spanmethod',
    _multiEditUseSpan() { return localStorage.getItem(this._ME_SPANMETHOD_KEY) !== '0'; },
    _multiEditSaveSelection() {
        const edi = el('editor');
        if (!edi || edi.selectionStart === edi.selectionEnd) return;
        const start = edi.selectionStart, end = edi.selectionEnd;
        const text = edi.value.substring(start, end);
        if (!text) return;
        this._multiEditSavedSelection = { start, end, text: text.normalize('NFC') };
    },

    toggleMultiEditBar() {
        const meBar = el('multi-edit-bar');
        const findBar = el('find-bar');
        if (!meBar) return;
        if (meBar.classList.contains('vis')) {
            if (this._multiEditUseSpan()) this._multiEditStripSpans();
            meBar.classList.remove('vis');
            App.updateFindHighlight(true);
            US.snap();
            TM.markDirty();
            this.render();
            return;
        }
        if (findBar && findBar.classList.contains('vis')) findBar.classList.remove('vis');
        const edi = el('editor');
        const selEl = el('me-select');
        const repEl = el('me-replace');
        const useSpan = this._multiEditUseSpan();
        let sel = '';
        if (edi && document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
            sel = edi.value.substring(edi.selectionStart, edi.selectionEnd).normalize('NFC');
        }
        if (!sel && this._multiEditSavedSelection && edi) {
            const s = this._multiEditSavedSelection;
            const current = edi.value.substring(s.start, s.end);
            if (current === s.text) sel = s.text;
        }
        if (sel && selEl) {
            selEl.value = sel;
            if (useSpan && edi) {
                if (document.activeElement === edi && edi.selectionStart !== edi.selectionEnd) {
                    const wrap = '<span style="' + this._multiEditSpanStyle + '">' + sel + '</span>';
                    edi.value = edi.value.split(sel).join(wrap);
                } else if (this._multiEditSavedSelection) {
                    const wrap = '<span style="' + this._multiEditSpanStyle + '">' + sel + '</span>';
                    edi.value = edi.value.substring(0, this._multiEditSavedSelection.start) + wrap + edi.value.substring(this._multiEditSavedSelection.end);
                }
            }
        }
        this._multiEditSavedSelection = null;
        if (repEl) repEl.value = (selEl && selEl.value) || '';
        meBar.classList.add('vis');