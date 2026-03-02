/* FM — File Manager (el, GH, TM, LocalFS, DelConfirm 의존) */

/* ═══════════════════════════════════════════════════════════
   FM — File Manager  (폴더 선택 → 파일 목록 → 탭 열기)
   File System Access API 사용 (Chrome/Edge 지원)
   Safari·Firefox: 미지원 → 파일 개별 선택 폴백
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   FM — File Manager
   ─ File System Access API (Chrome/Edge 86+)
   ─ FileSystemDirectoryHandle → IndexedDB 저장으로 세션 간 영속
   ─ 앱 재시작 시: IDB 복원 → requestPermission → 자동 로드
   ─ Firefox/Safari: 수동 선택 폴백
═══════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════
   FM — File Manager  v3  (IDB 파일 내용 캐시 방식)

   브라우저 보안 제약:
   - FileSystemDirectoryHandle은 앱 재시작 후 permission 리셋
   - requestPermission()은 사용자 클릭 없이 호출 불가
   → 해결: 파일 목록 + 내용을 IDB에 직접 캐시
            재시작 후 캐시로 즉시 복원, 실제 파일 동기화는 클릭 한 번

   IDB 스키마:
   - DB: 'mdpro-fm-v3'
   - store 'meta'  : key='root' → {folderName, fileCount, syncedAt}
   - store 'files' : key=상대경로 → {name, ext, folder, path, content, modified}
═══════════════════════════════════════════════════════════ */

/* GH → js/github/api.js, history.js, sync.js */

const FM = (() => {
    /* ── IDB ───────────────────────────────────────────── */
    const DB_NAME = 'mdpro-fm-v3';
    const DB_VER  = 1;
    let _db       = null;
    let _subHandles    = {};  /* path → FileSystemDirectoryHandle */
    let _currentSubDir = null; /* 현재 탐색 중인 하위 폴더 경로 */

    function _getDB() {
        if (_db) return Promise.resolve(_db);
        return new Promise((res, rej) => {
            const req = indexedDB.open(DB_NAME, DB_VER);
            req.onupgradeneeded = ev => {
                const db = ev.target.result;
                if (!db.objectStoreNames.contains('meta'))  db.createObjectStore('meta');
                if (!db.objectStoreNames.contains('files')) db.createObjectStore('files');
            };
            req.onsuccess = ev => { _db = ev.target.result; res(_db); };
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* IDB 단일 키 읽기 */
    async function _idbGet(store, key) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readonly').objectStore(store).get(key);
            req.onsuccess = ev => res(ev.target.result ?? null);
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* IDB 전체 키·값 읽기 */
    async function _idbAll(store) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const results = [];
            const req = db.transaction(store, 'readonly').objectStore(store).openCursor();
            req.onsuccess = ev => {
                const cur = ev.target.result;
                if (cur) { results.push(cur.value); cur.continue(); }
                else res(results);
            };
            req.onerror = ev => rej(ev.target.error);
        });
    }

    /* IDB 쓰기 */
    async function _idbPut(store, key, val) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readwrite').objectStore(store).put(val, key);
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* IDB 전체 삭제 */
    async function _idbClearStore(store) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readwrite').objectStore(store).clear();
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    async function _idbDel(store, key) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store, 'readwrite').objectStore(store).delete(key);
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* ── 상태 ─────────────────────────────────────────── */
    const hasAPI   = () => 'showDirectoryPicker' in window;
    let dirHandle  = null;   // FileSystemDirectoryHandle (세션 중에만 유효)
    let allFiles   = [];     // 현재 표시 중인 파일 목록
    let filtered   = [];
    let activeFile = null;
    let folderName = '';     // 폴더 이름 (표시용)
    let _searchQuery = '';   // 검색어 (search input)
    const FM_SHOW_HIDDEN_KEY = 'fm_show_hidden';
    let showHiddenFiles = localStorage.getItem(FM_SHOW_HIDDEN_KEY) === 'on';  /* 디폴트: 숨김 */

    function _isPathHidden(path) {
        return path.split('/').some(seg => seg.startsWith('.'));
    }
    function _applyFilters() {
        let base = showHiddenFiles ? allFiles : allFiles.filter(f => !_isPathHidden(f.path));
        filtered = _searchQuery
            ? base.filter(f => f.name.toLowerCase().includes(_searchQuery.toLowerCase()))
            : base;
    }

    /* ── 앱 시작: IDB 캐시에서 즉시 복원 ──────────────
       핸들 없이도 캐시된 목록/내용으로 파일 탭 채움     */
    async function restore() {
        try {
            showHiddenFiles = localStorage.getItem(FM_SHOW_HIDDEN_KEY) === 'on';
            const meta = await _idbGet('meta', 'root');
            if (!meta) return;
            folderName = meta.folderName;
            const cached = await _idbAll('files');
            if (!cached.length) return;
            allFiles   = cached;
            _applyFilters();
            /* DOM이 완전히 준비된 후 UI 업데이트 */
            setTimeout(() => {
                _setFolderUI(folderName, false);
                _render();
            }, 0);
        } catch (e) {
            console.warn('FM.restore:', e);
        }
    }

    /* ── 폴더 선택 ─────────────────────────────────────── */
    async function selectFolder() {
        if (!hasAPI()) { _noAPIFallback(); return; }
        try {
            const h = await window.showDirectoryPicker({ mode: 'readwrite' });
            dirHandle = h;
            folderName = h.name;
            _setFolderUI(folderName, 'syncing');
            await _syncFromHandle();                // 파일 읽기 + IDB 캐시 저장
            _setFolderUI(folderName, true);
        } catch (e) {
            if (e.name !== 'AbortError') console.warn('FM.selectFolder:', e);
        }
    }

    /* ── 실제 파일 시스템 → IDB 전체 동기화 ─────────────
       dirHandle이 활성(permission granted)일 때만 호출   */
    async function _syncFromHandle() {
        if (!dirHandle) return;
        const fresh = [];
        _emptyFolders = {};  /* 빈 폴더 목록 초기화 */
        await _scanDir(dirHandle, '', 0, fresh);
        allFiles = fresh;
        _applyFilters();
        /* IDB 캐시 저장 */
        await _idbClearStore('files');
        const db = await _getDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('files', 'readwrite');
            const st = tx.objectStore('files');
            fresh.forEach(f => st.put(f, f.path));
            tx.oncomplete = res;
            tx.onerror    = ev => rej(ev.target.error);
        });
        await _idbPut('meta', 'root', {
            folderName,
            fileCount: fresh.length,
            syncedAt: Date.now()
        });
        _render();
    }

    /* 빈 폴더도 추적 (폴더경로 → true) */
    let _emptyFolders = {};

    /* ── 디렉터리 재귀 스캔 ────────────────────────────── */
    async function _scanDir(handle, prefix, depth, out) {
        if (depth > 4) return;
        let hasChildren = false;
        for await (const entry of handle.values()) {
            hasChildren = true;
            if (entry.kind === 'directory') {
                const subPath = prefix ? `${prefix}/${entry.name}` : entry.name;
                _subHandles[subPath] = entry;   /* 하위 폴더 핸들 저장 */
                await _scanDir(entry, subPath, depth + 1, out);
            } else if (entry.kind === 'file') {
                const ext = entry.name.split('.').pop().toLowerCase();
                if (!['md','txt','html'].includes(ext)) continue;
                try {
                    const file    = await entry.getFile();
                    const content = await file.text();
                    out.push({
                        name    : entry.name,
                        ext,
                        folder  : prefix || '/',
                        path    : prefix ? `${prefix}/${entry.name}` : entry.name,
                        content,
                        modified: file.lastModified,
                    });
                } catch(e) { /* 읽기 실패 파일 스킵 */ }
            }
        }
        /* 이 폴더에 md/txt/html 파일이 없고 하위도 없으면 빈 폴더로 기록 */
        if (prefix) {
            const hasFiles = out.some(f => f.folder === prefix || f.path.startsWith(prefix + '/'));
            if (!hasFiles) _emptyFolders[prefix] = true;
        }
    }

    /* ── 새로고침: 폴더 재연결 or 캐시 재로드 ─────────── */
    async function refresh() {
        /* dirHandle이 있으면 실시간 동기화 시도 */
        if (dirHandle) {
            try {
                const perm = await dirHandle.queryPermission({ mode: 'read' });
                if (perm === 'granted') {
                    _setFolderUI(folderName, 'syncing');
                    await _syncFromHandle();
                    _setFolderUI(folderName, true);
                    return;
                }
            } catch(e) {}
        }
        /* 권한 없음 → 폴더 선택 다이얼로그 */
        await selectFolder();
    }

    /* ── 폴더 변경 ──────────────────────────────────────── */
    async function changeFolder() {
        dirHandle  = null;
        allFiles   = [];
        filtered   = [];
        folderName = '';
        _searchQuery = '';
        const searchInput = document.getElementById('files-search-input');
        if (searchInput) searchInput.value = '';
        await _idbClearStore('files');
        await _idbClearStore('meta');
        _render();
        await selectFolder();
    }

    /* ── UI 헤더 상태 표시 ────────────────────────────── */
    function _setFolderUI(name, state) {
        /* state: true(연결됨) | false(캐시,오프라인) | 'syncing' */
        const nameEl  = document.getElementById('files-folder-name');
        const selBtn  = document.getElementById('files-folder-btn');
        const refBtn  = document.getElementById('files-refresh-btn');
        const syncBar = document.getElementById('fm-sync-bar');
        if (syncBar) syncBar.style.display = (name && state !== 'syncing') ? '' : 'none';

        if (nameEl) {
            if (state === 'syncing') {
                nameEl.textContent = `⟳ 동기화 중…`;
                nameEl.style.color = 'var(--tx3)';
            } else if (state === true) {
                nameEl.textContent = `${name}  (${allFiles.length}개)`;
                nameEl.style.color = 'var(--tx2)';
            } else {
                /* 캐시 모드 */
                nameEl.innerHTML =
                    `<span style="color:var(--tx3);font-size:9px">📦 캐시</span> ${_esc(name)}`;
                nameEl.style.color = 'var(--tx3)';
            }
        }
        if (selBtn) {
            selBtn.textContent = (state !== false) ? '↺ 변경' : '🔄 재연결';
            selBtn.onclick     = (state !== false) ? changeFolder : refresh;
            selBtn.title       = (state === false)
                ? '폴더를 다시 선택하여 최신 파일을 동기화합니다'
                : '다른 폴더로 변경';
        }
        if (refBtn) refBtn.style.display = (state === true) ? '' : 'none';
        const openBtn = document.getElementById('files-open-btn');
        const foldBtn = document.getElementById('files-fold-toggle-btn');
        const hiddenBtn = document.getElementById('files-hidden-toggle-btn');
        if (openBtn) openBtn.style.display = (state === true && name) ? '' : 'none';
        if (foldBtn) foldBtn.style.display = (state === true && name) ? '' : 'none';
        if (hiddenBtn) {
            hiddenBtn.style.display = (state === true && name) ? '' : 'none';
            hiddenBtn.title = showHiddenFiles ? '숨김 파일 숨기기 (.git 등)' : '숨김 파일 표시 (.git 등)';
            hiddenBtn.classList.toggle('active', showHiddenFiles);
        }
    }

    /* ── 검색 ─────────────────────────────────────────── */
    function search(q) {
        _searchQuery = (q && q.trim()) ? q.trim() : '';
        _applyFilters();
        _render();
    }

    /* ── 숨김 파일 표시 토글 ───────────────────────────── */
    function toggleShowHidden() {
        showHiddenFiles = !showHiddenFiles;
        localStorage.setItem(FM_SHOW_HIDDEN_KEY, showHiddenFiles ? 'on' : 'off');
        _applyFilters();
        _setFolderUI(folderName, !!dirHandle);
        _render();
    }

    /* ── 전체 폴더 접기/펼치기 토글 ───────────────────── */
    function toggleFoldAll() {
        const list = document.getElementById('files-list');
        if (!list) return;
        const folders = list.querySelectorAll('.ft-folder');
        if (!folders.length) return;
        const anyExpanded = Array.from(folders).some(f => !f.classList.contains('collapsed'));
        const collapse = anyExpanded;
        folders.forEach(f => {
            const hdr = f.querySelector('.ft-folder-hdr');
            const toggle = hdr && hdr.querySelector('.ft-toggle');
            const isEmpty = toggle && toggle.textContent === '—';
            if (collapse) {
                f.classList.add('collapsed');
                if (toggle && !isEmpty) toggle.textContent = '▸';
            } else {
                f.classList.remove('collapsed');
                if (toggle && !isEmpty) toggle.textContent = '▾';
            }
        });
        const foldBtn = document.getElementById('files-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = collapse ? '▾' : '▽';
    }

    /* ── 파일 목록 렌더링 (트리 구조) ─────────────────── */
    function _render() {
        const list = document.getElementById('files-list');
        if (!list) return;
        list.innerHTML = '';

        if (!allFiles.length) {
            list.innerHTML =
                '<div class="files-empty">' +
                '<div style="font-size:28px;margin-bottom:8px">📁</div>' +
                '<div style="font-weight:600;margin-bottom:6px">폴더를 선택하세요</div>' +
                '<div style="color:var(--tx3);font-size:10px;line-height:1.7">.md / .txt / .html 파일<br>하위 폴더까지 트리로 탐색<br>내용이 캐시되어 재시작 후에도<br>즉시 열 수 있습니다</div>' +
                '</div>';
            return;
        }

        const src = filtered;
        if (!src.length) {
            list.innerHTML = '<div class="files-empty">검색 결과 없음</div>';
            return;
        }

        /* ── 트리 노드 빌드 ── */
        /* node: { name, children:{}, files:[] }  */
        const root = { name: '', children: {}, files: [] };

        src.forEach(f => {
            const parts = f.path.split('/');
            let node = root;
            for (let i = 0; i < parts.length - 1; i++) {
                const seg = parts[i];
                if (!node.children[seg]) node.children[seg] = { name: seg, children: {}, files: [] };
                node = node.children[seg];
            }
            node.files.push(f);
        });

        /* 빈 폴더(_emptyFolders)도 트리에 추가 (숨김 경로 제외) */
        const emptyFoldersToAdd = showHiddenFiles
            ? Object.keys(_emptyFolders)
            : Object.keys(_emptyFolders).filter(p => !_isPathHidden(p));
        emptyFoldersToAdd.sort().forEach(folderPath => {
            const parts = folderPath.split('/');
            let node = root;
            for (let i = 0; i < parts.length; i++) {
                const seg = parts[i];
                if (!node.children[seg]) node.children[seg] = { name: seg, children: {}, files: [], _fullPath: parts.slice(0, i+1).join('/') };
                node = node.children[seg];
            }
        });

        /* 트리 노드를 DOM으로 렌더 */
        function renderNode(node, depth, container) {
            const indent = depth * 12;

            /* 하위 폴더 먼저 (알파벳 순) */
            Object.keys(node.children).sort().forEach(folderName => {
                const child = node.children[folderName];
                /* _fullPath 보장 — 트리 빌드 시 누락된 경우 부모 경로로 계산 */
                if (!child._fullPath) {
                    child._fullPath = node._fullPath
                        ? node._fullPath + '/' + folderName
                        : folderName;
                }
                const totalFiles = countFiles(child);
                const isEmpty = totalFiles === 0;

                const folderEl = document.createElement('div');
                folderEl.className = 'ft-folder';

                const hdr = document.createElement('div');
                hdr.className = 'ft-folder-hdr';
                hdr.style.paddingLeft = (8 + indent) + 'px';
                hdr.innerHTML =
                    `<span class="ft-toggle">${isEmpty ? '—' : '▾'}</span>` +
                    `<span class="ft-folder-icon">📂</span>` +
                    `<span class="ft-folder-name">${_esc(folderName)}</span>` +
                    `<span class="ft-count" style="${isEmpty ? 'opacity:.4' : ''}">${isEmpty ? '빈 폴더' : totalFiles}</span>` +
                    `<button class="fg-add-btn" title="이 폴더에 새 파일 만들기" ` +
                    `onclick="event.stopPropagation();FM.createFileInFolder('${_esc(child._fullPath)}')">＋</button>` +
                    `<button class="folder-del-btn" title="${isEmpty ? '빈 폴더 삭제' : '폴더 삭제 (내부 파일 포함)'}" ` +
                    `data-path="${_esc(child._fullPath)}" data-empty="${isEmpty}" ` +
                    `onclick="event.stopPropagation();FM.confirmDeleteFolder(this)">🗑</button>`;
                hdr.onclick = () => {
                    folderEl.classList.toggle('collapsed');
                    hdr.querySelector('.ft-toggle').textContent =
                        folderEl.classList.contains('collapsed') ? '▸' : '▾';
                };
                folderEl.appendChild(hdr);

                const body = document.createElement('div');
                body.className = 'ft-folder-body';
                renderNode(child, depth + 1, body);
                folderEl.appendChild(body);
                container.appendChild(folderEl);
            });

            /* 파일 */
            node.files.sort((a, b) => (b.modified||0) - (a.modified||0)).forEach(f => {
                const row = document.createElement('div');
                const isAct = f.path === activeFile || f.name === activeFile;
                row.className = 'file-item' + (isAct ? ' active' : '');
                row.style.paddingLeft = (18 + indent) + 'px';
                const icon = f.ext === 'html' ? '🌐' : f.ext === 'txt' ? '📄' : '📝';
                const modStr = f.modified
                    ? new Date(f.modified).toLocaleDateString('ko', { month:'2-digit', day:'2-digit' })
                    : '';
                const sizeStr = f.size != null
                    ? (f.size >= 1048576
                        ? (f.size / 1048576).toFixed(1) + 'MB'
                        : f.size >= 1024
                            ? (f.size / 1024).toFixed(1) + 'KB'
                            : f.size + 'B')
                    : '';
                const metaStr = [sizeStr, modStr].filter(Boolean).join(' · ');
                const metaContent = sizeStr && modStr
                    ? `<span class="file-item-meta-size">${sizeStr}</span> · <span class="file-item-meta-date">${modStr}</span>`
                    : sizeStr ? `<span class="file-item-meta-size">${sizeStr}</span>` : modStr ? `<span class="file-item-meta-date">${modStr}</span>` : '';
                row.innerHTML =
                    `<span class="file-item-icon">${icon}</span>` +
                    `<span class="file-item-name">${_esc(f.name.replace(/\.[^.]+$/, ''))}</span>` +
                    `<span class="file-item-meta">${metaContent}</span>` +
                    `<button class="file-share-btn" title="mdliveData(GitHub)에 Push" onclick="event.stopPropagation();FM.pushToGH(this)" style="font-size:9px;padding:1px 4px">🐙</button>` +
                    `<button class="file-share-btn" title="md-viewer에 Push (공유)" onclick="event.stopPropagation();FM.pushToViewer(this)" style="font-size:9px;padding:1px 4px;color:#58c8f8">📤</button>` +
                    `<button class="file-move-btn" title="파일 이동" onclick="event.stopPropagation();FM.moveFile(this)">↗</button>` +
                    `<button class="file-del-btn" title="파일 삭제" onclick="event.stopPropagation();FM.confirmDelete(this)">🗑</button>`;
                row.title = f.path + (f.size != null ? '\n크기: ' + sizeStr : '') + (f.modified ? '\n수정: ' + new Date(f.modified).toLocaleString('ko') : '');
                row._fmFile = f;
                row.onclick = () => _openCached(f);
                container.appendChild(row);
            });
        }

        function countFiles(node) {
            let n = node.files.length;
            Object.values(node.children).forEach(c => { n += countFiles(c); });
            return n;
        }

        /* 루트 파일 + 폴더 트리 렌더 */
        renderNode(root, 0, list);
        /* 전체 접기 버튼: 렌더 후 기본은 모두 펼침 → ▽ */
        const foldBtn = document.getElementById('files-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = '▽';
    }

    /* ── 파일 열기 (캐시된 내용 사용 → 즉시 열림) ────── */
    function _openCached(f) {
        activeFile = f.name;
        document.querySelectorAll('.file-item').forEach(el =>
            el.classList.toggle('active', el.title.startsWith(f.path)));

        const name    = f.name.replace(/\.[^.]+$/, '');
        const ft      = f.ext === 'html' ? 'md' : f.ext;
        const content = f.ext === 'html'
            ? (TM._htmlToEditableContent || (x => x))(f.content)
            : f.content;

        /* 이미 열린 탭이면 전환 */
        const existing = TM.getAll().find(t => t.filePath === f.path || t.title === name);
        if (existing) { TM.switchTab(existing.id); return; }

        /* 새 탭으로 열기 */
        const tab = TM.newTab(name, content, ft);
        tab.filePath = f.path;
        TM.markClean(tab.id);
        TM.renderTabs();
        TM.persist();
    }

    /* ── 폴백 (API 미지원) ────────────────────────────── */
    function _noAPIFallback() {
        alert('폴더 선택 API는 Chrome/Edge에서만 지원됩니다.\n\n탭 바의 📂 열기 버튼으로 파일을 직접 여세요.');
    }

    function _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    /* ══════════════════════════════════════════════════════
       로컬 ↔ GitHub 동기화  (안전 설계)

       SHA 추적 구조:
         _baseSHAs  = { ghPath → sha }
                      마지막 pull/push 완료 시점의 원격 SHA
                      → "내 기준점" : 이후 변경 감지의 기준

       상태 분류 (파일별):
         same      : localSHA === remoteSHA  (변경 없음)
         local     : localSHA ≠ baseSHA, remoteSHA === baseSHA  (내가 변경)
         remote    : localSHA === baseSHA, remoteSHA ≠ baseSHA  (원격 변경)
         conflict  : 둘 다 baseSHA와 다름  (충돌)
         new-local : baseSHA 없고 원격도 없음  (내 신규)
         new-remote: baseSHA 없고 로컬도 없음  (원격 신규)

       push 안전 규칙:
         remote 또는 conflict 상태 파일이 하나라도 있으면 push 차단
         → "pull 먼저 실행하세요" 안내

       pull 동작:
         remote/conflict 파일의 GitHub 내용을 IDB 캐시에 반영
         conflict 파일은 사용자 확인 후 교체
         pull 완료 후 _baseSHAs를 원격 최신 SHA로 갱신
    ══════════════════════════════════════════════════════ */

    /* IDB에 기준 SHA 맵 저장/복원 */
    const BASE_SHA_KEY = 'fm_base_shas';
    let _baseSHAs = {};  // ghPath → sha  (마지막 sync 기준점)

    async function _loadBaseSHAs() {
        try {
            const db = await (async () => {
                return new Promise((res, rej) => {
                    const r = indexedDB.open('mdpro-fm-v3', 1);
                    r.onsuccess = e => res(e.target.result);
                    r.onerror   = e => rej(e.target.error);
                });
            })();
            const val = await new Promise((res, rej) => {
                const r = db.transaction('meta','readonly').objectStore('meta').get(BASE_SHA_KEY);
                r.onsuccess = e => res(e.target.result ?? {});
                r.onerror   = e => rej(e.target.error);
            });
            _baseSHAs = val || {};
        } catch(e) { _baseSHAs = {}; }
    }

    async function _saveBaseSHAs() {
        try {
            const db = await (async () => {
                return new Promise((res, rej) => {
                    const r = indexedDB.open('mdpro-fm-v3', 1);
                    r.onsuccess = e => res(e.target.result);
                    r.onerror   = e => rej(e.target.error);
                });
            })();
            await new Promise((res, rej) => {
                const r = db.transaction('meta','readwrite').objectStore('meta').put(_baseSHAs, BASE_SHA_KEY);
                r.onsuccess = () => res();
                r.onerror   = e => rej(e.target.error);
            });
        } catch(e) {}
    }

    /* ── blob SHA 계산 (git hash-object 호환) ─────────── */
    async function _blobSHA(content) {
        const enc  = new TextEncoder();
        const data = enc.encode(content);
        const hdr  = enc.encode('blob ' + data.byteLength);
        const buf  = new Uint8Array(hdr.length + 1 + data.length);
        buf.set(hdr, 0);
        buf[hdr.length] = 0;   /* NUL byte */
        buf.set(data, hdr.length + 1);
        const hashBuf = await crypto.subtle.digest('SHA-1', buf);
        return Array.from(new Uint8Array(hashBuf))
            .map(b => b.toString(16).padStart(2,'0')).join('');
    }

    /* ── 파일 상태 분류 ───────────────────────────────── */
    async function _classifyFiles(remoteSHAs) {
        if (!GH.isConnected()) return { files: [], hasConflict: false, hasRemote: false };
        const ghCfg = GH.cfg;
        const base  = ghCfg && ghCfg.basePath
            ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';

        const results = await Promise.all(allFiles.map(async f => {
            const ghPath   = base + f.path;
            const localSHA = await _blobSHA(f.content);
            const remoteSHA = remoteSHAs[ghPath] || null;
            const baseSHA   = _baseSHAs[ghPath]  || null;

            let status;
            if (!baseSHA && !remoteSHA) status = 'new-local';
            else if (!baseSHA && remoteSHA) {
                status = (localSHA === remoteSHA) ? 'same' : 'conflict';
            } else if (localSHA === remoteSHA)    status = 'same';
            else if (localSHA === baseSHA)         status = 'remote';   // 내가 안 바꿈, 원격만 바뀜
            else if (remoteSHA === baseSHA)        status = 'local';    // 내가 바꿈, 원격은 안 바뀜
            else                                   status = 'conflict'; // 둘 다 바뀜

            return { ...f, ghPath, localSHA, remoteSHA, baseSHA, status };
        }));

        /* 원격에만 있는 신규 파일 (로컬 캐시에 없음) */
        const localPaths = new Set(results.map(f => f.ghPath));
        Object.keys(remoteSHAs).forEach(ghPath => {
            if (!localPaths.has(ghPath)) {
                const base2 = ghCfg && ghCfg.basePath
                    ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
                if (!base2 || ghPath.startsWith(base2)) {
                    const name   = ghPath.split('/').pop();
                    const ext    = name.split('.').pop().toLowerCase();
                    if (['md','txt','html'].includes(ext)) {
                        const relPath = base2 ? ghPath.slice(base2.length) : ghPath;
                        const parts   = relPath.split('/');
                        const fname   = parts.pop();
                        results.push({
                            name: fname, ext, folder: parts.join('/') || '/',
                            path: relPath, ghPath,
                            localSHA: null, remoteSHA: remoteSHAs[ghPath],
                            baseSHA: _baseSHAs[ghPath] || null,
                            status: 'new-remote', content: null,
                        });
                    }
                }
            }
        });

        const hasConflict = results.some(f => f.status === 'conflict');
        const hasRemote   = results.some(f => f.status === 'remote' || f.status === 'new-remote');
        return { files: results, hasConflict, hasRemote };
    }

    /* ── UI 헬퍼 ──────────────────────────────────────── */
    function _syncStatus(cls, msg) {
        const el2 = document.getElementById('fm-sync-status');
        if (!el2) return;
        el2.className = cls;
        el2.textContent = msg;
    }
    function _setBusy(busy) {
        const pullBtn = document.getElementById('fm-pull-btn');
        const pushBtn = document.getElementById('fm-sync-btn');
        const pullIco = document.getElementById('fm-pull-icon');
        const pushIco = document.getElementById('fm-sync-icon');
        if (pullBtn) pullBtn.disabled = busy;
        if (pushBtn) pushBtn.disabled = busy;
        if (pullIco) pullIco.classList.toggle('icon-spin', busy);
        if (pushIco) pushIco.classList.toggle('icon-spin', busy);
    }

    /* ── PULL: GitHub → 로컬 캐시 ────────────────────────
       1. 원격 파일 SHA 맵 조회
       2. remote / new-remote / conflict 파일 분류
       3. conflict 파일: 사용자에게 "원격으로 덮어쓸까?" 확인
       4. 대상 파일 GitHub에서 내용 다운로드
       5. IDB 캐시 갱신 + allFiles 업데이트
       6. _baseSHAs를 현재 원격 SHA로 갱신 (기준점 이동)
       7. 이미 열린 탭에 "갱신됨" 알림                   */
    /* ── Clone URL 복사 (로컬 폴더용) ── */
    function cloneFromGitHub() {
        if (!GH.isConnected()) {
            alert('GitHub 연결이 설정되지 않았습니다.\n먼저 🐙 GitHub 탭에서 연결 설정을 완료하세요.');
            return;
        }
        const ghCfg = GH.cfg;
        const cloneUrl = `https://github.com/${ghCfg.repo}.git`;
        /* 클립보드 복사 + 안내 */
        navigator.clipboard.writeText(cloneUrl).then(() => {
            App._toast(`📋 Clone URL 복사됨: ${cloneUrl}`);
            /* 간단한 안내 모달 */
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
            ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid rgba(160,144,255,.35);border-radius:12px;padding:20px 22px;max-width:440px;width:100%;box-shadow:0 12px 50px rgba(0,0,0,.7)">
              <div style="font-size:13px;font-weight:700;color:#a090ff;margin-bottom:10px">📋 Clone URL 복사됨</div>
              <div style="font-size:11px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                터미널에서 아래 명령으로 로컬에 Clone하세요:
              </div>
              <div style="background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:9px 12px;font-family:var(--fm);font-size:11px;color:#a090ff;margin-bottom:14px;word-break:break-all">
                git clone ${cloneUrl}
              </div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:14px;line-height:1.6">
                Clone 후 <b style="color:var(--tx2)">로컬 폴더 열기</b>로 해당 폴더를 선택하면<br>
                Pull / Push로 GitHub와 동기화할 수 있습니다.
              </div>
              <div style="display:flex;justify-content:flex-end">
                <button id="clone-info-close" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
              </div>
            </div>`;
            document.body.appendChild(ov);
            document.getElementById('clone-info-close').onclick = () => ov.remove();
            ov.onclick = e => { if (e.target === ov) ov.remove(); };
        }).catch(() => {
            prompt('아래 URL을 복사해 git clone 하세요:', cloneUrl);
        });
    }

    async function pullFromGitHub() {
        if (!GH.isConnected()) {
            alert('GitHub 연결이 설정되지 않았습니다.\n먼저 🐙 GitHub 탭에서 연결 설정을 완료하세요.');
            return;
        }
        _setBusy(true);
        _syncStatus('ing', '⟳ 원격 상태 확인 중…');
        try {
            await _loadBaseSHAs();
            const remoteSHAs = await GH.getRemoteSHAs();
            const { files, hasConflict, hasRemote } = await _classifyFiles(remoteSHAs);

            const toFetch = files.filter(f =>
                f.status === 'remote' || f.status === 'new-remote');
            const conflicts = files.filter(f => f.status === 'conflict');

            /* 충돌 파일 처리 */
            let pullConflicts = [];
            if (conflicts.length) {
                const names = conflicts.map(f => `  • ${f.name}`).join('\n');
                const ok = confirm(
                    `⚠ 충돌 파일 ${conflicts.length}개:\n${names}\n\n` +
                    `로컬과 원격 모두 변경되었습니다.\n` +
                    `원격 내용으로 덮어쓰시겠습니까?\n\n` +
                    `(취소: 충돌 파일은 그대로 유지)`
                );
                if (ok) pullConflicts = conflicts;
            }

            const allToPull = [...toFetch, ...pullConflicts];

            if (!allToPull.length && !hasRemote) {
                _syncStatus('ok', '✓ 이미 최신 상태입니다');
                _setBusy(false);
                return;
            }

            _syncStatus('ing', `⟳ ${allToPull.length}개 파일 다운로드 중…`);

            /* GitHub에서 내용 다운로드 */
            const ghCfg = GH.cfg;
            let pulled = 0;
            for (const f of allToPull) {
                try {
                    const data = await fetch(
                        `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(f.ghPath)}?ref=${ghCfg.branch}`,
                        { headers: {
                            'Authorization': `token ${ghCfg.token}`,
                            'Accept': 'application/vnd.github.v3+json',
                        }}
                    ).then(r => r.json());

                    const content = decodeURIComponent(
                        escape(atob(data.content.replace(/\n/g, '')))
                    );

                    /* IDB 캐시 + allFiles 갱신 */
                    const idx = allFiles.findIndex(af => af.path === f.path);
                    const updated = {
                        name    : f.name,
                        ext     : f.ext,
                        folder  : f.folder,
                        path    : f.path,
                        content,
                        modified: Date.now(),
                    };
                    if (idx >= 0) allFiles[idx] = updated;
                    else          allFiles.push(updated);

                    /* IDB에 저장 */
                    const db = await (async () => new Promise((res, rej) => {
                        const r = indexedDB.open('mdpro-fm-v3', 1);
                        r.onsuccess = e => res(e.target.result);
                        r.onerror   = e => rej(e.target.error);
                    }))();
                    await new Promise((res, rej) => {
                        const r = db.transaction('files','readwrite')
                            .objectStore('files').put(updated, updated.path);
                        r.onsuccess = () => res();
                        r.onerror   = e => rej(e.target.error);
                    });

                    /* 이미 열린 탭에 갱신 알림 */
                    _notifyOpenTab(f.name.replace(/\.[^.]+$/, ''), content, f.path);

                    pulled++;
                } catch(e2) {
                    console.warn('pull failed for', f.path, e2);
                }
            }

            /* _baseSHAs 갱신 (기준점 이동) */
            files.forEach(f => {
                if (f.remoteSHA) _baseSHAs[f.ghPath] = f.remoteSHA;
            });
            await _saveBaseSHAs();

            filtered = allFiles;
            _render();
            _syncStatus('ok', `✓ ${pulled}개 pull 완료`);

        } catch(e) {
            console.error('FM.pullFromGitHub:', e);
            _syncStatus('err', `✗ ${e.message}`);
        } finally {
            _setBusy(false);
        }
    }

    /* pull 후 이미 열린 탭에 알림 */
    function _notifyOpenTab(title, newContent, filePath) {
        const tab = TM.getAll().find(t =>
            t.filePath === filePath || t.title === title);
        if (!tab) return;
        /* 탭에 갱신 뱃지 표시 */
        tab._updatedContent = newContent;
        const titleEl = document.querySelector(`.tab[data-id="${tab.id}"] .tab-title`);
        if (titleEl && !titleEl.querySelector('.tab-updated-badge')) {
            titleEl.insertAdjacentHTML('afterend',
                '<span class="tab-updated-badge" title="원격에서 갱신됨 — 클릭하여 적용">NEW</span>');
        }
        /* 현재 활성 탭이면 toast 알림 */
        if (TM.getActive() && TM.getActive().id === tab.id) {
            App._toast(`↓ "${title}" — 원격에서 갱신됨. 탭의 NEW 배지를 클릭하면 적용됩니다.`);
        }
    }

    /* ── PUSH: 로컬 캐시 → GitHub ────────────────────────
       안전 규칙:
         ① 원격에 변경이 있으면 push 차단 → pull 먼저
         ② 충돌이 있으면 push 차단 → pull 후 해결
         ③ 통과 시 local + new-local 파일만 push
         ④ push 완료 후 _baseSHAs 갱신                   */
    async function syncToGitHub() {
        if (!allFiles.length) {
            alert('먼저 로컬 폴더를 선택하고 파일을 불러오세요.');
            return;
        }
        if (!GH.isConnected()) {
            const go = confirm('GitHub 연결이 설정되지 않았습니다.\n설정 화면을 여시겠습니까?');
            if (go) { SB.switchTab('files'); SB.switchSource('github'); GH.showSettings(); }
            return;
        }

        _setBusy(true);
        _syncStatus('ing', '⟳ 원격 상태 확인 중…');

        try {
            await _loadBaseSHAs();
            const remoteSHAs = await GH.getRemoteSHAs();
            const { files, hasConflict, hasRemote } = await _classifyFiles(remoteSHAs);

            /* ① 원격 변경 / 충돌 차단 */
            if (hasConflict) {
                const names = files.filter(f => f.status === 'conflict')
                    .map(f => `  🔴 ${f.name}`).join('\n');
                _syncStatus('err', `✗ 충돌 ${files.filter(f=>f.status==='conflict').length}개 — pull 후 해결하세요`);
                alert(`Push 차단: 충돌 파일이 있습니다.\n${names}\n\n먼저 Pull을 실행하여 충돌을 해결하세요.`);
                _setBusy(false);
                return;
            }
            if (hasRemote) {
                const names = files.filter(f => f.status === 'remote' || f.status === 'new-remote')
                    .map(f => `  🔵 ${f.name}`).join('\n');
                _syncStatus('warn', `⚠ 원격 변경 있음 — pull 먼저 실행하세요`);
                alert(`Push 차단: 원격에서 변경된 파일이 있습니다.\n${names}\n\n먼저 Pull을 실행하여 최신 내용을 가져오세요.`);
                _setBusy(false);
                return;
            }

            /* ② push 대상: local + new-local 만 */
            const toPush = files.filter(f =>
                f.status === 'local' || f.status === 'new-local');

            if (!toPush.length) {
                _syncStatus('ok', '✓ 변경사항 없음 — GitHub와 동일합니다');
                _setBusy(false);
                return;
            }

            /* ③ 커밋 메시지 */
            const summary = toPush.length <= 3
                ? toPush.map(f => f.name).join(', ')
                : `${toPush.length}개 파일`;
            const msg = prompt(
                `Push할 파일 ${toPush.length}개:\n` +
                toPush.map(f => `  ${f.status === 'new-local' ? '➕' : '✏'} ${f.name}`).join('\n') +
                '\n\n커밋 메시지:',
                `Update ${summary}`
            );
            if (msg === null) { _setBusy(false); _syncStatus('', ''); return; }

            _syncStatus('ing', `⟳ ${toPush.length}개 파일 push 중…`);

            /* ④ Git Data API로 일괄 push */
            const result = await GH.pushLocalFiles(
                toPush.map(f => ({ path: f.ghPath, content: f.content })),
                msg || `Update ${summary}`
            );

            /* ⑤ _baseSHAs 갱신 */
            const newRemote = await GH.getRemoteSHAs();
            toPush.forEach(f => {
                if (newRemote[f.ghPath]) _baseSHAs[f.ghPath] = newRemote[f.ghPath];
            });
            await _saveBaseSHAs();

            _syncStatus('ok',
                `✓ ${result.pushed}개 push 완료  #${result.commitSha}`);
            App._toast(`✓ GitHub push 완료 — ${result.pushed}개 파일 (#${result.commitSha})`);
            _render();

        } catch(e) {
            console.error('FM.syncToGitHub:', e);
            _syncStatus('err', `✗ ${e.message}`);
        } finally {
            _setBusy(false);
        }
    }

    /* clone 완료 후 GH가 호출 → 원격 SHA를 기준점으로 설정 */
    function _setBaseSHAsFromRemote(remoteSHAs, basePath) {
        const base = basePath ? basePath.replace(/\/$/, '') + '/' : '';
        Object.keys(remoteSHAs).forEach(ghPath => {
            _baseSHAs[ghPath] = remoteSHAs[ghPath];
        });
        _saveBaseSHAs();
    }

    /* ── 특정 폴더에 파일 만들기 (폴더 그룹 헤더 + 클릭) ───── */
    async function createFileInFolder(folderPath) {
        _currentSubDir = folderPath === '/' ? null : folderPath;
        await createLocalFile();
        _currentSubDir = null;
    }

    /* ── 새 폴더 만들기 ─────────────────────────────────── */
    async function createFolder() {
        if (!dirHandle) { alert('먼저 폴더를 선택하세요.'); return; }

        /* 부모 폴더 선택 UI */
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        Object.keys(_subHandles).sort().forEach(p => {
            const depth = p.split('/').length - 1;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center';
        const box = document.createElement('div');
        box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
        box.innerHTML = `
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                <span style="font-size:14px;font-weight:700;color:var(--txh)">📁 새 폴더 만들기</span>
                <button id="fm-ndir-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
            </div>
            <div style="margin-bottom:12px">
                <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (부모 폴더)</label>
                <select id="fm-ndir-parent" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer">
                    ${parentOptions.map(o => '<option value="' + o.value + '"' + (defaultParent !== undefined && o.value === defaultParent ? ' selected' : '') + '>' + o.label + '</option>').join('')}
                </select>
            </div>
            <div style="margin-bottom:16px">
                <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">폴더 이름</label>
                <input id="fm-ndir-name" type="text" value="새폴더"
                    style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                <div id="fm-ndir-err" style="display:none;margin-top:5px;font-size:11px;color:#f76a6a">⚠ 폴더 이름에 앞뒤 공백이 있습니다. 공백을 제거해주세요.</div>
            </div>
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="fm-ndir-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                <button id="fm-ndir-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
            </div>`;
        ov.appendChild(box);
        document.body.appendChild(ov);

        const nameInput = document.getElementById('fm-ndir-name');
        const parentSel = document.getElementById('fm-ndir-parent');
        setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

        const result = await new Promise(resolve => {
            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('fm-ndir-close').onclick = () => close(null);
            document.getElementById('fm-ndir-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('fm-ndir-ok').onclick = () => {
                const raw = nameInput.value;
                const trimmed = raw.trim();
                const errEl = document.getElementById('fm-ndir-err');
                if (!trimmed) { nameInput.focus(); return; }
                if (raw !== trimmed) {
                    /* 앞뒤 공백 있음 → 에러 표시, 입력란 테두리 강조 */
                    errEl.style.display = 'block';
                    nameInput.style.borderColor = '#f76a6a';
                    nameInput.focus();
                    nameInput.setSelectionRange(0, raw.length);
                    return;
                }
                errEl.style.display = 'none';
                nameInput.style.borderColor = '';
                close({ parentVal: parentSel.value, name: trimmed });
            };
            nameInput.addEventListener('input', () => {
                /* 입력 중 에러 해소 시 실시간으로 숨김 */
                const errEl = document.getElementById('fm-ndir-err');
                if (nameInput.value === nameInput.value.trim()) {
                    errEl.style.display = 'none';
                    nameInput.style.borderColor = '';
                }
            });
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('fm-ndir-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });

        if (!result) return;

        const safe = result.name.replace(/[/\\:*?"<>|]/g, '_');
        const parentHandle = result.parentVal
            ? (_subHandles[result.parentVal] || dirHandle)
            : dirHandle;

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { alert('쓰기 권한이 거부되었습니다.'); return; }
            const newHandle = await parentHandle.getDirectoryHandle(safe, { create: true });
            const where = result.parentVal ? result.parentVal + '/' + safe : safe;
            /* 새 폴더 핸들 즉시 등록 + 빈 폴더로 표시 */
            _subHandles[where] = newHandle;
            _emptyFolders[where] = true;
            App._toast('📁 "' + where + '" 폴더 생성됨');
            _render();  /* 즉시 UI 반영 */
            /* 백그라운드로 전체 재스캔 */
            _subHandles = {};
            _emptyFolders = {};
            await _syncFromHandle();
        } catch(e) {
            if (e.name === 'NotAllowedError') {
                if (confirm('쓰기 권한이 필요합니다. 폴더를 다시 선택하시겠습니까?')) selectFolder();
            } else { alert('폴더 생성 실패: ' + e.message); }
        }
    }

    /* ── 현재 폴더에 새 파일 만들기 (폴더 선택 UI 포함) ── */
    async function createLocalFile() {
        if (!dirHandle) { alert('먼저 폴더를 선택하세요.'); return; }
        /* 선택 가능한 폴더 목록: 루트 + _subHandles의 모든 폴더 */
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        Object.keys(_subHandles).sort().forEach(p => {
            const depth = p.split('/').length - 1;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });
        /* 빈 폴더도 포함 */
        Object.keys(_emptyFolders).sort().forEach(p => {
            if (!_subHandles[p]) {
                const depth = p.split('/').length - 1;
                folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
            }
        });

        /* 폴더 선택 모달 표시 */
        const chosen = await _showNewFileModal(folderOptions);
        if (!chosen) return;  /* 취소 */

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[/\\:*?"<>|]/g, '_');

        const targetHandle = folderVal
            ? (_subHandles[folderVal] || await (async () => {
                /* _subHandles에 없으면 dirHandle에서 직접 경로 탐색 */
                try {
                    const parts = folderVal.split('/');
                    let h = dirHandle;
                    for (const p of parts) { h = await h.getDirectoryHandle(p); }
                    _subHandles[folderVal] = h;
                    return h;
                } catch(e2) { return null; }
            })())
            : dirHandle;
        if (!targetHandle) { alert('폴더 핸들을 찾을 수 없습니다. 새로고침 후 다시 시도하세요.'); return; }

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { alert('쓰기 권한이 거부되었습니다.'); return; }
            const fh = await targetHandle.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('');
            await wr.close();
            const where = folderVal ? folderVal + '/' + safe : safe;
            App._toast('📄 "' + where + '" 생성됨');
            const title = safe.replace(/\.[^.]+$/, '');
            const tab = TM.newTab(title, '', 'md');
            tab.filePath    = where;
            tab._fileHandle = fh;
            TM.markClean(tab.id);
            TM.renderTabs();
            _emptyFolders = {};
            _subHandles = {};
            await _syncFromHandle();
        } catch(e) {
            if (e.name === 'NotAllowedError') {
                if (confirm('쓰기 권한이 필요합니다. 폴더를 다시 선택하시겠습니까?')) selectFolder();
            } else { alert('파일 생성 실패: ' + e.message); }
        }
    }

    /* ── 새 파일 만들기 모달 (폴더 선택 + 파일명 입력) ─── */
    function _showNewFileModal(folderOptions) {
        return new Promise(resolve => {
            /* 기존 모달 제거 */
            const existing = document.getElementById('fm-newfile-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'fm-newfile-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:340px;max-width:460px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';

            const selOptions = folderOptions.map(o =>
                `<option value="${o.value}">${o.label}</option>`
            ).join('');

            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📄 새 파일 만들기</span>
                    <button id="fm-nf-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">저장 폴더 선택</label>
                    <select id="fm-nf-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer">
                        ${selOptions}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">파일 이름 <span style="opacity:.6">(.md 자동 추가)</span></label>
                    <input id="fm-nf-name" type="text" value="Untitled"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box"
                        placeholder="파일명을 입력하세요">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fm-nf-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="fm-nf-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('fm-nf-name');
            const folderSel = document.getElementById('fm-nf-folder');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            /* 현재 선택된 서브폴더가 있으면 기본값으로 */
            if (_currentSubDir) {
                const opt = [...folderSel.options].find(o => o.value === _currentSubDir);
                if (opt) folderSel.value = _currentSubDir;
            }

            const close = (result) => { ov.remove(); resolve(result); };

            document.getElementById('fm-nf-close').onclick = () => close(null);
            document.getElementById('fm-nf-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('fm-nf-ok').onclick = () => {
                const fn = nameInput.value.trim();
                if (!fn) { nameInput.focus(); return; }
                close({ folderVal: folderSel.value, filename: fn });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('fm-nf-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 로컬 파일 삭제 확인 & 실행 ────────────────────── */
    function confirmDelete(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;
        DelConfirm.show({
            name : f.name,
            path : f.path,
            type : 'local',
            onConfirm: async () => {
                try {
                    /* File System Access API: 부모 폴더 핸들에서 removeEntry */
                    const parentPath = (f.folder && f.folder !== '/') ? f.folder : '';

                    /* 1) 캐시에서 먼저 탐색
                       2) 없으면 dirHandle에서 경로 세그먼트를 따라 직접 탐색 (공백 포함 경로 대응) */
                    let parentHandle = parentPath ? _subHandles[parentPath] : dirHandle;
                    if (parentPath && !parentHandle) {
                        try {
                            let h = dirHandle;
                            for (const seg of parentPath.split('/')) {
                                h = await h.getDirectoryHandle(seg);
                            }
                            parentHandle = h;
                            _subHandles[parentPath] = h; /* 캐시 등록 */
                        } catch(e2) { parentHandle = null; }
                    }

                    if (!parentHandle) throw new Error('폴더 핸들 없음 — 폴더를 다시 선택해주세요');

                    /* 쓰기 권한 요청 */
                    const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
                    if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

                    /* 실제 파일 삭제 */
                    await parentHandle.removeEntry(f.name);

                    /* IDB 캐시에서도 제거 */
                    await _idbDel('files', f.path);
                    allFiles = allFiles.filter(x => x.path !== f.path);
                    _applyFilters();

                    /* 열려 있는 탭이면 닫기 */
                    const tab = TM.getAll().find(t => t.filePath === f.path || t.title === f.name.replace(/\.[^.]+$/, ''));
                    if (tab) TM.closeTab(tab.id);

                    _render();
                    App._toast(`🗑 ${f.name} 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    /* ── 로컬 파일 → mdliveData(GitHub) Push ── */
    async function pushToGH(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;
        if (!GH.isConnected()) { alert('GitHub(mdliveData) 연결 설정이 필요합니다'); return; }

        /* f.content는 _scanDir에서 이미 로드됨 */
        const content = f.content;
        if (content === undefined || content === null) {
            alert('파일 내용을 불러올 수 없습니다. 폴더를 새로고침 후 다시 시도하세요.');
            return;
        }

        btn.textContent = '⟳'; btn.disabled = true;
        try {
            const ghCfg  = GH.cfg;
            const base   = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const path   = base + f.name;
            /* 기존 파일 SHA 조회 (없으면 신규 생성) */
            let sha = null;
            try {
                const info = await fetch(
                    `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(path)}?ref=${ghCfg.branch}`,
                    { headers: { 'Authorization': `token ${ghCfg.token}`, 'Accept': 'application/vnd.github.v3+json' } }
                ).then(r => r.ok ? r.json() : null);
                if (info?.sha) sha = info.sha;
            } catch(e) {}

            const b64  = btoa(unescape(encodeURIComponent(content)));
            const body = { message: `Upload: ${f.name}`, content: b64, branch: ghCfg.branch };
            if (sha) body.sha = sha;

            const res = await fetch(
                `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(path)}`,
                {
                    method : 'PUT',
                    headers: {
                        'Authorization': `token ${ghCfg.token}`,
                        'Accept': 'application/vnd.github.v3+json',
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(body),
                }
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(`GitHub ${res.status}: ${err.message || res.statusText}`);
            }
            btn.textContent = '🐙'; btn.disabled = false;
            App._toast(`🐙 mdliveData Push 완료: ${f.name}`);
            GH._render();
        } catch(e) {
            btn.textContent = '🐙'; btn.disabled = false;
            alert('push 실패: ' + e.message);
        }
    }

    /* ── 로컬 파일 → md-viewer Push ── */
    async function pushToViewer(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;

        /* f.content는 _scanDir에서 이미 로드됨 */
        const content = f.content;
        if (content === undefined || content === null) {
            alert('파일 내용을 불러올 수 없습니다. 폴더를 새로고침 후 다시 시도하세요.');
            return;
        }

        btn.textContent = '⟳'; btn.disabled = true;
        try {
            btn.textContent = '📤'; btn.disabled = false;
            await PVShare.quickPush({ name: f.name, content });
        } catch(e) {
            btn.textContent = '📤'; btn.disabled = false;
            alert('push 실패: ' + e.message);
        }
    }

    /* ── 로컬 폴더 삭제 ────────────────────────────────── */
    async function confirmDeleteFolder(btn) {
        const folderPath = btn.dataset.path;
        const isEmpty    = btn.dataset.empty === 'true';
        if (!folderPath || !dirHandle) return;

        /* 폴더 핸들 확인 — 없으면 부모에서 재탐색 */
        let fHandle = _subHandles[folderPath];
        if (!fHandle) {
            /* 부모 핸들에서 직접 탐색 시도 */
            try {
                const parts2 = folderPath.split('/');
                const leafName = parts2.pop();
                const parentPath2 = parts2.join('/');
                const parentH = parentPath2 ? (_subHandles[parentPath2] || dirHandle) : dirHandle;
                if (parentH) fHandle = await parentH.getDirectoryHandle(leafName);
                if (fHandle) _subHandles[folderPath] = fHandle;
            } catch(e2) { /* silent */ }
        }
        if (!fHandle) {
            alert('폴더 핸들을 찾을 수 없습니다. 새로고침(↻) 후 다시 시도하세요.');
            return;
        }

        /* 확인 모달 */
        const filesInFolder = allFiles.filter(f =>
            f.folder === folderPath || f.path.startsWith(folderPath + '/')
        );
        const fileCount = filesInFolder.length;

        const confirmed = await _showFolderDeleteModal(folderPath, isEmpty, fileCount);
        if (!confirmed) return;

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 부모 핸들 찾기 */
            const parts = folderPath.split('/');
            const folderName = parts.pop();
            const parentPath = parts.join('/');
            const parentHandle = parentPath ? (_subHandles[parentPath] || dirHandle) : dirHandle;

            if (!parentHandle) throw new Error('부모 폴더 핸들 없음');

            /* 재귀 삭제 (recursive: true) — Chrome 91+ 지원 */
            await parentHandle.removeEntry(folderName, { recursive: true });

            /* 메모리·IDB에서 제거 */
            const removed = allFiles.filter(f =>
                f.folder === folderPath || f.path.startsWith(folderPath + '/')
            );
            for (const f of removed) {
                await _idbDel('files', f.path);
                /* 열려있는 탭도 닫기 */
                const tab = TM.getAll().find(t => t.filePath === f.path);
                if (tab) TM.closeTab(tab.id);
            }
            allFiles  = allFiles.filter(f => f.folder !== folderPath && !f.path.startsWith(folderPath + '/'));
            _applyFilters();
            delete _subHandles[folderPath];
            delete _emptyFolders[folderPath];

            App._toast(`🗑 "${folderPath}" 폴더 삭제 완료`);
            _render();
        } catch(e) {
            alert('폴더 삭제 실패: ' + (e.message || e));
        }
    }

    function _showFolderDeleteModal(folderPath, isEmpty, fileCount) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const folderName = folderPath.split('/').pop();
            const warnHtml = isEmpty
                ? `<div style="font-size:11px;color:#6af7b0;margin-top:6px">✅ 빈 폴더입니다. 안전하게 삭제됩니다.</div>`
                : `<div style="font-size:11px;color:#f7a06a;margin-top:6px;line-height:1.7">
                    ⚠ 이 폴더 안의 <b style="color:#ff8080">${fileCount}개 파일</b>이 모두 영구 삭제됩니다.<br>
                    삭제된 파일은 복구할 수 없습니다.
                   </div>`;

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:2px solid rgba(247,106,106,.4);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;gap:9px;margin-bottom:14px">
                    <span style="font-size:20px">🗑</span>
                    <span style="font-size:14px;font-weight:700;color:#f76a6a">폴더 삭제</span>
                </div>
                <div style="background:rgba(247,106,106,.08);border:1px solid rgba(247,106,106,.3);border-radius:8px;padding:12px 14px;margin-bottom:14px">
                    <div style="font-size:11px;color:var(--tx3);margin-bottom:4px">삭제할 폴더</div>
                    <div style="font-size:14px;font-weight:700;color:#f76a6a">${_esc(folderName)}</div>
                    <div style="font-size:10px;color:var(--tx3);font-family:var(--fm)">${_esc(folderPath)}</div>
                    ${warnHtml}
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fdel-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="fdel-ok" style="padding:6px 18px;border-radius:6px;border:none;background:rgba(247,106,106,.2);border:1px solid rgba(247,106,106,.5);color:#f76a6a;font-size:12px;font-weight:700;cursor:pointer">🗑 삭제 확인</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('fdel-cancel').onclick = () => close(false);
            ov.onclick = (e) => { if (e.target === ov) close(false); };
            document.getElementById('fdel-ok').onclick = () => close(true);
        });
    }

    /* ── 로컬 파일 이동 ────────────────────────────────── */
    async function moveFile(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._fmFile;
        if (!f) return;

        /* 이동 가능한 폴더 목록 (현재 폴더 제외) */
        const currentFolder = f.folder || '/';
        const folderOptions = [{ label: '📁 (루트)', value: '/' }];
        Object.keys(_subHandles).sort().forEach(p => {
            if (p !== currentFolder) {
                const depth = p.split('/').length - 1;
                folderOptions.push({
                    label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')',
                    value: p
                });
            }
        });
        Object.keys(_emptyFolders).sort().forEach(p => {
            if (p !== currentFolder && !_subHandles[p]) {
                const depth = p.split('/').length - 1;
                folderOptions.push({
                    label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')',
                    value: p
                });
            }
        });

        const destFolder = await _showMoveModal(f.name, folderOptions);
        if (destFolder === null) return;  /* 취소 */

        const destPath = destFolder === '/' ? f.name : destFolder + '/' + f.name;
        if (destPath === f.path) { App._toast('같은 폴더입니다'); return; }

        try {
            const perm = await dirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 원본 파일 읽기 */
            const srcParentPath = f.folder === '/' ? '' : f.folder;
            const srcParentHandle = srcParentPath ? (_subHandles[srcParentPath] || dirHandle) : dirHandle;
            const srcFileHandle = await srcParentHandle.getFileHandle(f.name);
            const srcFile = await srcFileHandle.getFile();
            const srcContent = await srcFile.text();

            /* 대상 폴더에 파일 쓰기 */
            const destFolderPath = destFolder === '/' ? '' : destFolder;
            const destHandle = destFolderPath ? (_subHandles[destFolderPath] || dirHandle) : dirHandle;
            const newFH = await destHandle.getFileHandle(f.name, { create: true });
            const wr = await newFH.createWritable();
            await wr.write(srcContent);
            await wr.close();

            /* 원본 삭제 */
            await srcParentHandle.removeEntry(f.name);

            /* 탭의 filePath 업데이트 */
            const tab = TM.getAll().find(t => t.filePath === f.path);
            if (tab) {
                tab.filePath = destPath;
                tab._fileHandle = newFH;
                TM.renderTabs();
            }

            /* IDB 갱신 */
            await _idbDel('files', f.path);
            _subHandles = {};
            _emptyFolders = {};
            await _syncFromHandle();
            App._toast(`✅ "${f.name}" → "${destFolder === '/' ? '루트' : destFolder}" 이동 완료`);
        } catch(e) {
            alert('파일 이동 실패: ' + (e.message || e));
        }
    }

    function _showMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';
            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 파일 이동</span>
                    <button id="fmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_esc(fileName)}</b>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="fmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="fmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('fmov-close').onclick = () => close(null);
            document.getElementById('fmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('fmov-ok').onclick = () => {
                close(document.getElementById('fmov-dest').value);
            };
        });
    }

    /* ── 로컬 폴더를 탐색기에서 열기 (FM 스코프) ──
       브라우저 정책으로 직접 열 수 없으면 모달로 주소 표시 + 자동 복사 */
    const FOPEN_SAVE_KEY = 'fm_custom_folder_path_';
    function openInExplorer() {
        if (!dirHandle) { App._toast('⚠ 폴더를 먼저 선택하세요'); return; }
        const defaultPath = folderName;
        const savedPath = localStorage.getItem(FOPEN_SAVE_KEY + defaultPath);
        const initialValue = (savedPath && savedPath.trim()) ? savedPath : defaultPath;
        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';
        ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:440px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📂 폴더 열기 안내</span>
                    <button id="fopen-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:11px;color:var(--tx3);margin-bottom:12px;line-height:1.6">
                    브라우저 보안 정책으로 해당 폴더를 직접 열 수 없습니다.<br>
                    아래 폴더 주소를 수정·저장하거나 복사하여 탐색기 주소창에 붙여넣으세요.
                </div>
                <input type="text" id="fopen-path" style="width:100%;box-sizing:border-box;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:10px 12px;font-size:12px;font-family:monospace;color:var(--tx2);margin-bottom:14px;outline:none">
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fopen-save" style="padding:6px 14px;border-radius:6px;border:1px solid rgba(88,200,248,.4);background:rgba(88,200,248,.15);color:#58c8f8;font-size:12px;cursor:pointer">💾 저장</button>
                    <button id="fopen-copy" style="padding:6px 14px;border-radius:6px;border:1px solid rgba(106,247,176,.4);background:rgba(106,247,176,.15);color:#6af7b0;font-size:12px;cursor:pointer">📋 복사</button>
                    <button id="fopen-ok" style="padding:6px 14px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
                </div>
            </div>`;
        document.body.appendChild(ov);
        const pathInput = document.getElementById('fopen-path');
        if (pathInput) pathInput.value = initialValue;
        const getValue = () => (pathInput && pathInput.value) ? pathInput.value.trim() : defaultPath;
        const doCopy = () => {
            const val = getValue();
            navigator.clipboard.writeText(val).then(() => {
                App._toast('📋 폴더 주소가 복사되었습니다');
            }).catch(() => {
                const ta = document.createElement('textarea');
                ta.value = val;
                ta.style.cssText = 'position:fixed;left:-9999px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
                App._toast('📋 폴더 주소가 복사되었습니다');
            });
        };
        const doSave = () => {
            const val = getValue();
            if (val) {
                localStorage.setItem(FOPEN_SAVE_KEY + defaultPath, val);
                App._toast('💾 저장되었습니다');
            }
        };
        doCopy();  /* 창 열림과 동시에 자동 복사 */
        document.getElementById('fopen-close').onclick = () => ov.remove();
        document.getElementById('fopen-ok').onclick = () => ov.remove();
        document.getElementById('fopen-save').onclick = () => doSave();
        document.getElementById('fopen-copy').onclick = () => doCopy();
        ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
    }

    return { restore, selectFolder, changeFolder, refresh, search, openInExplorer, toggleFoldAll, toggleShowHidden,
             syncToGitHub, pullFromGitHub, cloneFromGitHub, createFolder, createLocalFile, createFileInFolder,
             confirmDelete, confirmDeleteFolder, moveFile, pushToGH, pushToViewer,
             getFiles: () => allFiles,
             getFolderName: () => folderName,
             _setBaseSHAsFromRemote, _render };
})();