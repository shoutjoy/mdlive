/* TM — Tab Manager (el, US, Persist, GH 의존) */
const TM = (() => {
    const STORE_KEY = typeof Persist !== 'undefined' ? Persist.KEY : 'mdpro_tabs_v1';
    let tabs     = [];   // [{id,title,content,isDirty,filePath,fileType,undoSt,undoPtr}]
    let activeId = null;
    let _nextId  = 1;

    /* ── 탭 객체 팩토리 ──────────────────────────────── */
    function _makeTab(title = 'Untitled', content = '', fileType = 'md') {
        return { id: _nextId++, title, content,
                 isDirty: false, filePath: null, fileType,
                 undoSt: [content], undoPtr: 0 };
    }

    /* ── localStorage 영속 (Persist 사용) ───────────────── */
    function persist() {
        if (typeof Persist !== 'undefined' && Persist.save) {
            Persist.save(tabs, activeId, _nextId);
            return;
        }
        try {
            localStorage.setItem(STORE_KEY, JSON.stringify({
                tabs: tabs.map(t => ({
                    id: t.id, title: t.title, content: t.content,
                    filePath: t.filePath, fileType: t.fileType
                })),
                activeId, nextId: _nextId
            }));
        } catch(e) {}
    }

    function _restore() {
        if (typeof Persist !== 'undefined' && Persist.load) {
            const d = Persist.load();
            if (!d) return false;
            _nextId = d.nextId || d.tabs.length + 1;
            tabs = d.tabs.map(t => _makeTab(t.title, t.content, t.fileType || 'md'));
            d.tabs.forEach((src, i) => { tabs[i].id = src.id; tabs[i].filePath = src.filePath || null; });
            activeId = d.tabs.some(t => t.id === d.activeId) ? d.activeId : tabs[0].id;
            return true;
        }
        try {
            const d = JSON.parse(localStorage.getItem(STORE_KEY));
            if (!d || !d.tabs || !d.tabs.length) return false;
            _nextId = d.nextId || d.tabs.length + 1;
            tabs = d.tabs.map(t => _makeTab(t.title, t.content, t.fileType || 'md'));
            d.tabs.forEach((src, i) => { tabs[i].id = src.id; tabs[i].filePath = src.filePath || null; });
            activeId = d.tabs.some(t => t.id === d.activeId) ? d.activeId : tabs[0].id;
            return true;
        } catch(e) { return false; }
    }

    /* ── undo 상태 백업 / 복원 ──────────────────────── */
    function _saveUndo() {
        const t = _active();
        if (!t) return;
        try { const s = US._getState(); t.undoSt = s.stack; t.undoPtr = s.ptr; } catch(e) {}
    }
    function _loadUndo(t) {
        try { US._setState(t.undoSt || [t.content], t.undoPtr ?? 0); } catch(e) { US.snap(); }
    }

    /* ── 에디터 ↔ 탭 IO ─────────────────────────────── */
    function _pushToEditor(tab) {
        const edi = el('editor'), ti = el('doc-title');
        if (edi) { edi.value = tab.content; edi.setSelectionRange(0, 0); }
        if (ti)  ti.value = tab.title;
        /* 상단 타이틀바 — 탭과 동일한 텍스트 표시 */
        _updateTitlebar(tab);
    }

    function _updateTitlebar(tab) {
        const titleDisp = el('titlebar-path-display');
        if (!titleDisp) return;
        /* 상단 타이틀: 파일명만 (확장자 제거) — 탭은 경로 포함, 상단은 파일명만 */
        const fullText = tab.ghPath ? tab.ghPath : tab.title;
        const fileName = fullText.split('/').pop().replace(/\.[^.]+$/, '');
        titleDisp.textContent = fileName || tab.title;
        titleDisp.title = fullText;  /* 호버 시 전체 경로 툴팁 */
    }
    function _pullFromEditor() {
        const t = _active();
        if (!t) return;
        const edi = el('editor'), ti = el('doc-title');
        if (edi) t.content = edi.value;
        if (ti)  t.title   = ti.value;
    }

    /* ── 탭 UI 렌더 ──────────────────────────────────── */
    function renderTabs() {
        const list = document.getElementById('tab-list');
        if (!list) return;
        list.innerHTML = '';

        tabs.forEach(t => {
            const div = document.createElement('div');
            div.className = 'tab' +
                (t.id === activeId ? ' active' : '') +
                (t.isDirty ? ' dirty' : '');
            div.dataset.id = t.id;
            div.title = t.ghPath ? t.ghPath : (t.filePath ? t.filePath : t.title);

            /* 탭에 표시할 텍스트: ghPath가 있으면 경로/파일명 형식으로 */
            const tabDisplayText = t.ghPath ? t.ghPath : t.title;

            div.innerHTML =
                `<span class="tab-icon">${_icon(t.fileType)}</span>` +
                (t.ghPath ? `<span class="tab-gh-indicator" title="GitHub: ${_esc(t.ghPath)}">🐙</span>` : '') +
                `<span class="tab-title">${_esc(tabDisplayText)}</span>` +
                `<span class="tab-dirty" title="저장되지 않은 변경사항">●</span>` +
                `<button class="tab-close" title="닫기 (Ctrl+W)">✕</button>`;

            /* 클릭: 전환 / 닫기 */
            div.addEventListener('click', ev => {
                if (ev.target.classList.contains('tab-close')) { closeTab(t.id); return; }
                switchTab(t.id);
            });
            /* 더블클릭: 제목 인라인 편집 */
            div.querySelector('.tab-title').addEventListener('dblclick', ev => {
                ev.stopPropagation();
                _renameInline(t.id, div.querySelector('.tab-title'));
            });
            /* 중간 버튼: 닫기 */
            div.addEventListener('mousedown', ev => {
                if (ev.button === 1) { ev.preventDefault(); closeTab(t.id); }
            });
            list.appendChild(div);
        });

        /* 모두저장 버튼 dirty 상태 표시 (항상 노출) */
        const btn = document.getElementById('tab-save-all-btn');
        if (btn) btn.classList.toggle('has-dirty', tabs.some(t => t.isDirty));
    }

    function _icon(ft) {
        return ft === 'html' ? '🌐' : ft === 'txt' ? '📄' : '📝';
    }
    function _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    /* ── 탭 전환 ─────────────────────────────────────── */
    function switchTab(id) {
        if (id === activeId) return;
        _pullFromEditor();
        _saveUndo();

        activeId = id;
        const tab = _active();
        if (!tab) return;

        _pushToEditor(tab);
        _loadUndo(tab);
        renderTabs();
        persist();
        App.render();
        el('editor') && el('editor').focus();
        /* 활성 탭이 GitHub 파일이면 폴더 뷰를 GitHub로, 로컬 파일이면 로컬로 자동 전환 */
        if (typeof SB !== 'undefined' && SB.currentSource) {
            const wantSource = tab.ghPath ? 'github' : 'local';
            if (SB.currentSource() !== wantSource) SB.switchSource(wantSource);
        }
        if (typeof GH !== 'undefined' && GH.syncHighlightFromActiveTab) GH.syncHighlightFromActiveTab();
    }

    /* ── 새 탭 ───────────────────────────────────────── */
    function newTab(title, content, fileType) {
        _pullFromEditor();
        _saveUndo();
        const tab = _makeTab(title || 'Untitled', content || '', fileType || 'md');
        tabs.push(tab);
        activeId = tab.id;
        _pushToEditor(tab);
        US._setState([tab.content], 0);
        renderTabs();
        persist();
        App.render();
        setTimeout(() => el('editor') && el('editor').focus(), 50);
        return tab;
    }

    /* ── 탭 복제 (현재 활성 탭 → copy_ 접두사 새 탭) ─── */
    function duplicateTab() {
        _pullFromEditor();
        const src = _active();
        if (!src) return;
        const newTitle = 'copy_' + (src.title || 'Untitled');
        const tab = newTab(newTitle, src.content, src.fileType || 'md');
        tab.filePath = null;
        tab.ghPath = null;
        tab.ghBranch = null;
        tab.ghSha = null;
        persist();
    }

    /* ── 탭 닫기 ─────────────────────────────────────── */
    function closeTab(id) {
        const tab = tabs.find(t => t.id === id);
        if (!tab) return;
        if (tab.isDirty &&
            !confirm(`'${tab.title}' 의 변경사항이 저장되지 않았습니다.\n닫으시겠습니까?`)) return;

        const idx    = tabs.indexOf(tab);
        const wasActive = id === activeId;
        tabs.splice(idx, 1);

        if (tabs.length === 0) {
            /* 마지막 탭을 닫은 경우: 빈 탭 하나 자동 생성 (파일은 항상 한 개 열려 있음) */
            newTab('Untitled', '', 'md');
            return;
        }

        if (wasActive) {
            /* 오른쪽 탭 → 없으면 왼쪽 탭으로 이동 */
            const next = tabs[idx] || tabs[idx - 1];
            activeId = next.id;
            _pushToEditor(next);
            _loadUndo(next);
            App.render();
        }
        renderTabs();
        persist();
    }

    /* ── dirty 관리 ──────────────────────────────────── */
    function markDirty() {
        const t = _active();
        if (!t || t.isDirty) return;      /* 이미 dirty면 DOM 조작 생략 */
        t.isDirty = true;
        const el2 = document.querySelector(`.tab[data-id="${activeId}"]`);
        if (el2) el2.classList.add('dirty');
        /* 모두저장 버튼 dirty 표시 */
        const btn = document.getElementById('tab-save-all-btn');
        if (btn) btn.classList.add('has-dirty');
    }

    function markClean(id) {
        const t = tabs.find(t => t.id === (id ?? activeId));
        if (!t) return;
        t.isDirty = false;
        const el2 = document.querySelector(`.tab[data-id="${t.id}"]`);
        if (el2) el2.classList.remove('dirty');
    }

    /* ── 파일 열기 ───────────────────────────────────── */
    function openFile() {
        const inp = document.getElementById('tab-file-input');
        if (inp) inp.click();
    }

    /* HTML 파일에서 마크다운으로 변환 가능한 텍스트 추출 */
    function _htmlToEditableContent(htmlStr) {
        try {
            const parser = new DOMParser();
            const doc    = parser.parseFromString(htmlStr, 'text/html');
            const body   = doc.body;
            if (!body) return htmlStr;

            /* preview-page div들 순서대로 내용 추출 */
            const pages = body.querySelectorAll('.preview-page');
            if (pages.length > 0) {
                return Array.from(pages).map(pg => {
                    /* page-break 유지 */
                    return _nodeToMd(pg) + '\n\n<div class="page-break"></div>';
                }).join('\n').replace(/(<div class="page-break"><\/div>\n*)$/, '').trim();
            }
            /* preview-page 없으면 body 전체 텍스트 변환 */
            return _nodeToMd(body);
        } catch(e) {
            return htmlStr;
        }
    }

    /* DOM 노드를 마크다운으로 변환 (헤딩, 굵기, 단락 등 기본 처리) */
    function _nodeToMd(root) {
        const lines = [];
        function walk(node) {
            if (node.nodeType === 3) { /* TEXT_NODE */
                const t = node.textContent;
                if (t.trim()) lines.push(t);
                return;
            }
            if (node.nodeType !== 1) return;
            const tag = node.tagName.toLowerCase();
            if (tag === 'h1') { lines.push('\n# ' + node.textContent.trim() + '\n'); }
            else if (tag === 'h2') { lines.push('\n## ' + node.textContent.trim() + '\n'); }
            else if (tag === 'h3') { lines.push('\n### ' + node.textContent.trim() + '\n'); }
            else if (tag === 'h4') { lines.push('\n#### ' + node.textContent.trim() + '\n'); }
            else if (tag === 'hr') { lines.push('\n---\n'); }
            else if (tag === 'p') { lines.push('\n' + _inlineToMd(node) + '\n'); }
            else if (tag === 'ul') {
                node.querySelectorAll(':scope > li').forEach(li => lines.push('- ' + _inlineToMd(li)));
                lines.push('');
            }
            else if (tag === 'ol') {
                let n = 1;
                node.querySelectorAll(':scope > li').forEach(li => { lines.push(n++ + '. ' + _inlineToMd(li)); });
                lines.push('');
            }
            else if (tag === 'blockquote') { lines.push('> ' + node.textContent.trim()); }
            else if (tag === 'pre') { lines.push('\n```\n' + node.textContent + '\n```\n'); }
            else if (tag === 'table') {
                const rows = node.querySelectorAll('tr');
                rows.forEach((row, ri) => {
                    const cells = Array.from(row.querySelectorAll('th,td')).map(c => c.textContent.trim());
                    lines.push('| ' + cells.join(' | ') + ' |');
                    if (ri === 0) lines.push('| ' + cells.map(() => '---').join(' | ') + ' |');
                });
                lines.push('');
            }
            else { node.childNodes.forEach(walk); }
        }
        root.childNodes.forEach(walk);
        return lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    }

    function _inlineToMd(node) {
        let out = '';
        node.childNodes.forEach(c => {
            if (c.nodeType === 3) { out += c.textContent; return; }
            if (c.nodeType !== 1) return;
            const tag = c.tagName.toLowerCase();
            if (tag === 'b' || tag === 'strong') out += '**' + c.textContent + '**';
            else if (tag === 'i' || tag === 'em') out += '*' + c.textContent + '*';
            else if (tag === 'code') out += '`' + c.textContent + '`';
            else if (tag === 'a') out += '[' + c.textContent + '](' + (c.href || '#') + ')';
            else if (tag === 'sup') out += '[^' + c.textContent + ']';
            else out += _inlineToMd(c);
        });
        return out;
    }

    function _onFileSelected(ev) {
        const files = [...(ev.target.files || [])];
        files.forEach(file => {
            const reader = new FileReader();
            reader.onload = e => {
                const rawText = e.target.result;
                const ext     = file.name.split('.').pop().toLowerCase();
                const ft      = ['md','txt','html'].includes(ext) ? ext : 'md';
                const name    = file.name.replace(/\.[^.]+$/, '');

                /* HTML 파일: body 내용을 마크다운으로 변환하여 편집 가능하게 */
                const text = (ft === 'html') ? _htmlToEditableContent(rawText) : rawText;

                /* 동일 파일 이미 열려 있으면 덮어쓰기 확인 */
                const dup = tabs.find(t => t.filePath === file.name || t.title === name);
                if (dup) {
                    if (!dup.isDirty || confirm(`'${dup.title}' 이(가) 이미 열려 있습니다.\n다시 불러오시겠습니까?`)) {
                        dup.content  = text;
                        dup.title    = name;
                        dup.filePath = file.name;
                        dup.fileType = ft;
                        dup.isDirty  = false;
                        if (dup.id === activeId) { _pushToEditor(dup); App.render(); }
                        else switchTab(dup.id);
                        renderTabs(); persist();
                    }
                    return;
                }

                const tab = newTab(name, text, ft === 'html' ? 'md' : ft);
                tab.filePath = file.name;
                markClean(tab.id);
                renderTabs(); persist();
            };
            reader.readAsText(file, 'UTF-8');
        });
        ev.target.value = '';
    }

    /* ── 일괄 저장 (.md) ─────────────────────────────── */
    function saveAll() {
        _pullFromEditor();
        let saved = 0;
        tabs.forEach(tab => {
            if (!tab.isDirty && !tab.filePath && tab.content === '') return;
            const fname = (tab.title || 'document').replace(/[^a-z0-9가-힣\-_. ]/gi, '_');
            dlBlob(tab.content, fname + '.md', 'text/markdown;charset=utf-8');
            tab.isDirty = false;
            saved++;
        });
        if (saved === 0) { alert('저장할 변경사항이 없습니다.'); return; }
        renderTabs(); persist();
    }

    /* ── 탭 제목 인라인 편집 ─────────────────────────── */
    function _renameInline(id, el2) {
        const tab = tabs.find(t => t.id === id);
        if (!tab) return;
        const orig = tab.title;
        el2.contentEditable = 'true';
        el2.focus();
        const sel = window.getSelection();
        const rng = document.createRange();
        rng.selectNodeContents(el2);
        sel.removeAllRanges(); sel.addRange(rng);

        const commit = () => {
            el2.contentEditable = 'false';
            const v = el2.textContent.trim() || orig;
            tab.title = v;
            el2.textContent = v;
            if (id === activeId) { const ti = el('doc-title'); if (ti) ti.value = v; }
            persist();
        };
        el2.onblur    = commit;
        el2.onkeydown = e => {
            if (e.key === 'Enter')  { e.preventDefault(); commit(); }
            if (e.key === 'Escape') { el2.textContent = orig; el2.contentEditable = 'false'; }
        };
    }

    /* ── doc-title 입력 → 탭 제목 동기화 ────────────── */
    function syncTitle(v) {
        const t = _active();
        if (!t) return;
        if (t.title === v) return;
        t.title = v;
        /* 탭 전체 재렌더 — ghPath가 있는 탭은 경로/파일명 전체가 유지됨 */
        renderTabs();
        /* 상단 타이틀바 (파일명만) */
        _updateTitlebar(t);
        persist();
    }

    /* ── 초기화 ──────────────────────────────────────── */
    function init() {
        if (!_restore()) {
            /* 구버전 단일 파일 마이그레이션 */
            try {
                const old = JSON.parse(localStorage.getItem('mdpro_v7') || '{}');
                tabs.push(_makeTab(old.t || 'Untitled', old.c || '', 'md'));
            } catch(e) {
                tabs.push(_makeTab());
            }
            activeId = tabs[0].id;
        }
        _pushToEditor(_active());
        _loadUndo(_active());
        renderTabs();

        /* tab-list 가로 휠 스크롤 */
        const tl = document.getElementById('tab-list');
        if (tl) tl.addEventListener('wheel', e => {
            if (e.deltaY !== 0) { e.preventDefault(); tl.scrollLeft += e.deltaY; }
        }, { passive: false });
    }

    function _active() { return tabs.find(t => t.id === activeId) || null; }

    return {
        init, newTab, duplicateTab, switchTab, closeTab,
        openFile, saveAll, markDirty, markClean,
        syncTitle, renderTabs, persist,
        saveFromEditor: _pullFromEditor,
        getActive: _active, getAll: () => tabs,
        _onFileSelected, _htmlToEditableContent,
    };
})();

