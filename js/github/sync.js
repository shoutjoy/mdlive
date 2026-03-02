/* GH — GitHub File Manager (sync.js) — GHApi, GHHistory 의존 */
/* ═══════════════════════════════════════════════════════════
   GH — GitHub File Manager
   ─ GitHub REST API v3 (api.github.com)
   ─ PAT(Personal Access Token) + owner/repo 기반 인증
   ─ 파일 목록: GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1
   ─ 파일 읽기: GET /repos/{owner}/{repo}/contents/{path}
   ─ 파일 저장: PUT /repos/{owner}/{repo}/contents/{path}  (SHA 필요)
   ─ 설정 저장: localStorage (토큰은 암호화 없이 저장 — 신뢰 기기 전제)
   ─ 파일 목록 캐시: IDB 'mdpro-gh-v1' (재시작 후 즉시 표시)
═══════════════════════════════════════════════════════════ */
const GH = (() => {

    /* ── 설정 저장/복원 ───────────────────────────────── */
    const CFG_KEY = 'mdpro_gh_cfg';

    function _loadCfg() {
        try { return JSON.parse(localStorage.getItem(CFG_KEY) || 'null'); } catch(e) { return null; }
    }
    function _saveCfg(cfg) {
        try { localStorage.setItem(CFG_KEY, JSON.stringify(cfg)); } catch(e) {}
    }

    let cfg = _loadCfg();
    // cfg = { token, repo:'owner/repo', branch:'main', basePath:'' }

    /* ── IDB 캐시 (파일 목록 + 내용) ─────────────────── */
    const GH_DB = 'mdpro-gh-v1';
    let _ghdb = null;

    function _ghDB() {
        if (_ghdb) return Promise.resolve(_ghdb);
        return new Promise((res, rej) => {
            const req = indexedDB.open(GH_DB, 1);
            req.onupgradeneeded = ev => {
                const db = ev.target.result;
                if (!db.objectStoreNames.contains('files')) db.createObjectStore('files');
                if (!db.objectStoreNames.contains('meta'))  db.createObjectStore('meta');
            };
            req.onsuccess = ev => { _ghdb = ev.target.result; res(_ghdb); };
            req.onerror   = ev => rej(ev.target.error);
        });
    }
    async function _ghGet(store, key) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store,'readonly').objectStore(store).get(key);
            req.onsuccess = ev => res(ev.target.result ?? null);
            req.onerror   = ev => rej(ev.target.error);
        });
    }
    async function _ghPut(store, key, val) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store,'readwrite').objectStore(store).put(val, key);
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }
    async function _ghAll(store) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const rows = [];
            const req = db.transaction(store,'readonly').objectStore(store).openCursor();
            req.onsuccess = ev => {
                const cur = ev.target.result;
                if (cur) { rows.push(cur.value); cur.continue(); }
                else res(rows);
            };
            req.onerror = ev => rej(ev.target.error);
        });
    }
    async function _ghClear(store) {
        const db = await _ghDB();
        return new Promise((res, rej) => {
            const req = db.transaction(store,'readwrite').objectStore(store).clear();
            req.onsuccess = () => res();
            req.onerror   = ev => rej(ev.target.error);
        });
    }

    /* ── 상태 ─────────────────────────────────────────── */
    let allFiles  = [];   // [{name, ext, path, sha, size, modified}]
    let filtered  = [];
    let activeFile = null;
    let _fileContentCache = {};  // path → {content, sha} (세션 캐시)
    let _ghEmptyFolders = {};    // folderRelPath → true (.gitkeep 기반 빈 폴더)

    /* ── GitHub API 헬퍼 (GHApi 사용) ──────────────────────────────── */
    function _apiBase() { return typeof GHApi !== 'undefined' ? GHApi.base(cfg) : null; }
    async function _apiFetch(path, opts = {}) {
        if (typeof GHApi === 'undefined') throw new Error('GHApi 로드 필요');
        return GHApi.fetch(cfg, path, opts);
    }

    /* ── 설정 모달 ────────────────────────────────────── */
    function showSettings() {
        const el2 = id => document.getElementById(id);
        const devName = localStorage.getItem('mdpro_device_name') || '';
        if (cfg) {
            el2('gh-token-input').value  = cfg.token    || '';
            el2('gh-repo-input').value   = cfg.repo     || '';
            el2('gh-branch-input').value = cfg.branch   || 'main';
            el2('gh-path-input').value   = cfg.basePath || '';
        } else {
            if (el2('gh-branch-input')) el2('gh-branch-input').value = 'main';
        }
        if (el2('gh-device-input')) el2('gh-device-input').value = devName;
        /* md-viewer 저장소 표시 */
        const pvsEl = el2('pvs-repo-inline');
        if (pvsEl) {
            try {
                const pvcfg = JSON.parse(localStorage.getItem('pvshare_cfg') || '{}');
                pvsEl.value = pvcfg.repo || '';
            } catch(e) {}
        }
        /* 앱 소스 주소 복원 */
        const appSrcSaved = localStorage.getItem('mdpro_app_src');
        const appSrcLnk = el2('app-src-link');
        if (appSrcSaved && appSrcLnk) {
            appSrcLnk.href = 'https://github.com/' + appSrcSaved;
            appSrcLnk.textContent = appSrcSaved + ' ↗';
        }
        const st = el2('gh-conn-status');
        if (st) { st.className = ''; st.textContent = ''; }
        App.showModal('gh-modal');
        /* 모달 내 자동새로고침 버튼/시간표시 동기화 */
        _ghArUpdateBtn();
        _ghArUpdateCountdown();
    }

    function hideSettings() { App.hideModal('gh-modal'); }

    /** 헤더의 연결 테스트 버튼: 저장된 설정으로 연결 테스트만 수행 (설정 없으면 설정창 열기) */
    async function handleHdrSaveClick(ev) {
        if (ev) ev.stopPropagation();
        const currentCfg = cfg || _loadCfg();
        if (!currentCfg || !currentCfg.token || !currentCfg.repo) {
            showSettings();
            return;
        }
        const nameEl = document.getElementById('gh-repo-name');
        if (nameEl) { nameEl.textContent = '⟳ 연결 테스트 중…'; nameEl.style.color = 'var(--tx3)'; }
        try {
            const info = await _apiFetch('');
            cfg = currentCfg;
            _setRepoUI(cfg.repo);
            const hdrOk = document.getElementById('gh-hdr-ok-msg');
            if (hdrOk) {
                hdrOk.textContent = '연결성공';
                hdrOk.style.display = 'inline';
                hdrOk.style.opacity = '1';
                clearTimeout(hdrOk._hideTid);
                hdrOk._hideTid = setTimeout(() => {
                    hdrOk.style.opacity = '0';
                    setTimeout(() => { hdrOk.style.display = 'none'; hdrOk.textContent = ''; }, 280);
                }, 2200);
            }
            refresh();
        } catch (e) {
            cfg = _loadCfg();
            _setRepoUI(currentCfg.repo, 'err');
            const saveBtn = document.getElementById('gh-hdr-save-btn');
            if (saveBtn) saveBtn.classList.remove('gh-hdr-save-connected');
            if (typeof App !== 'undefined' && App._toast) App._toast('✗ 연결 실패: ' + (e.message || e));
            else alert('연결 실패: ' + (e.message || e));
        }
    }

    async function saveSettings() {
        const eid = id => document.getElementById(id);
        const tokenEl = eid('gh-token-input');
        if (!tokenEl) {
            showSettings();
            return;
        }
        const token    = tokenEl.value.trim();
        const repoEl   = eid('gh-repo-input');
        const repo     = (repoEl && repoEl.value ? repoEl.value : '').trim();
        const branchEl = eid('gh-branch-input');
        const branch   = (branchEl && branchEl.value ? branchEl.value : '') || 'main';
        const pathEl   = eid('gh-path-input');
        const basePath = (pathEl && pathEl.value ? pathEl.value : '').trim().replace(/^\/|\/$/g, '');
        const device   = eid('gh-device-input') ? eid('gh-device-input').value.trim() : '';
        if (device) localStorage.setItem('mdpro_device_name', device);
        else        localStorage.removeItem('mdpro_device_name');
        /* md-viewer 저장소 저장 */
        const pvsInline = eid('pvs-repo-inline');
        if (pvsInline && pvsInline.value.trim()) {
            try {
                const pvcfg = JSON.parse(localStorage.getItem('pvshare_cfg') || '{}');
                pvcfg.repo = pvsInline.value.trim();
                localStorage.setItem('pvshare_cfg', JSON.stringify(pvcfg));
            } catch(e) {}
        }
        const st       = eid('gh-conn-status');

        if (!token || !repo || !repo.includes('/')) {
            _setStatus('err', '토큰과 저장소(owner/repo)를 모두 입력하세요');
            return;
        }

        _setStatus('loading', '⟳ 연결 테스트 중…');
        cfg = { token, repo, branch, basePath };

        try {
            /* 연결 테스트: 저장소 정보 조회 */
            const info = await _apiFetch('');
            _setStatus('ok', `✓ 연결 성공 — ${info.full_name}  (${info.visibility})`);
            _saveCfg(cfg);
            _setRepoUI(cfg.repo);
            /* #gh-hdr에 연결성공 메시지 표시 후 사라지게 */
            const hdrOk = document.getElementById('gh-hdr-ok-msg');
            if (hdrOk) {
                hdrOk.textContent = '연결성공';
                hdrOk.style.display = 'inline';
                hdrOk.style.opacity = '1';
                clearTimeout(hdrOk._hideTid);
                hdrOk._hideTid = setTimeout(() => {
                    hdrOk.style.opacity = '0';
                    setTimeout(() => { hdrOk.style.display = 'none'; hdrOk.textContent = ''; }, 280);
                }, 2200);
            }
            /* 즉시 파일 목록 로드 */
            setTimeout(() => {
                hideSettings();
                refresh();
            }, 900);
        } catch(e) {
            _setStatus('err', `✗ ${e.message}`);
            cfg = _loadCfg(); // 롤백
        }
    }

    function _setStatus(cls, msg) {
        const st = document.getElementById('gh-conn-status');
        if (!st) return;
        st.className = cls;
        st.textContent = msg;
    }

    /* ── 초기화: IDB 캐시에서 즉시 복원 ─────────────────
       재시작/새로고침 후 설정이 있으면 캐시 목록 표시     */
    async function restore() {
        cfg = _loadCfg();
        if (!cfg) return;
        try {
            const cached = await _ghAll('files');
            if (!cached.length) return;
            allFiles = cached;
            filtered = allFiles;
            /* IDB에서 마지막 HEAD SHA 복원 (변경 감지용) */
            try {
                const rootMeta = await _ghGet('meta', 'root');
                if (rootMeta && rootMeta.headSha) _ghLastHeadSha = rootMeta.headSha;
            } catch (_) {}
            /* IDB에서 빈 폴더 목록 복원 */
            try {
                const ef = await _ghGet('meta', 'emptyFolders');
                if (ef && ef.folders) {
                    _ghEmptyFolders = {};
                    ef.folders.forEach(p => { _ghEmptyFolders[p] = true; });
                }
            } catch(e2) { _ghEmptyFolders = {}; }
            _setRepoUI(cfg.repo);
            setTimeout(() => _render(), 0);
        } catch(e) {
            console.warn('GH.restore:', e);
        }
    }

    /* ── 파일 목록 로드 (API) ──────────────────────────── */
    async function refresh() {
        if (!cfg) { showSettings(); return; }
        _setRepoUI(cfg.repo, 'loading');
        try {
            /* Git Trees API: 재귀적으로 전체 트리 한 번에 가져옴 */
            const tree = await _apiFetch(
                `/git/trees/${cfg.branch}?recursive=1`
            );
            const EXT  = ['md','txt','html'];
            const base = cfg.basePath ? cfg.basePath + '/' : '';

            /* .gitkeep가 있는 폴더 = 빈 폴더로 별도 추적 */
            _ghEmptyFolders = {};
            tree.tree.forEach(item => {
                if (item.type !== 'blob') return;
                if (!item.path.endsWith('.gitkeep')) return;
                if (base && !item.path.startsWith(base)) return;
                const rel = base ? item.path.slice(base.length) : item.path;
                const parts = rel.split('/');
                parts.pop(); // .gitkeep 제거
                const folderRel = parts.join('/');
                if (folderRel) _ghEmptyFolders[folderRel] = true;
            });

            allFiles = tree.tree
                .filter(item => {
                    if (item.type !== 'blob') return false;
                    const ext = item.path.split('.').pop().toLowerCase();
                    if (!EXT.includes(ext)) return false;
                    if (base && !item.path.startsWith(base)) return false;
                    return true;
                })
                .map(item => {
                    const rel  = base ? item.path.slice(base.length) : item.path;
                    const parts = rel.split('/');
                    const name = parts.pop();
                    const folder = parts.join('/') || '/';
                    return {
                        name,
                        ext   : name.split('.').pop().toLowerCase(),
                        folder,
                        path  : item.path,   // GitHub full path
                        sha   : item.sha,
                        size  : item.size,
                        date  : null,         // 파일별 마지막 커밋 날짜 (lazy load)
                    };
                });

            filtered = allFiles;

            /* IDB 캐시 갱신 */
            await _ghClear('files');
            const db = await _ghDB();
            await new Promise((res, rej) => {
                const tx = db.transaction('files','readwrite');
                const st = tx.objectStore('files');
                allFiles.forEach(f => st.put(f, f.path));
                tx.oncomplete = res;
                tx.onerror    = ev => rej(ev.target.error);
            });
            const headSha = await _ghGetHeadSha();
            _ghLastHeadSha = headSha || _ghLastHeadSha;
            await _ghPut('meta','root', { repo: cfg.repo, count: allFiles.length, at: Date.now(), headSha: _ghLastHeadSha });
            /* .gitkeep 빈 폴더 목록도 IDB에 저장 */
            await _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) });
            _setRepoUI(cfg.repo, 'ok');
            _render();
        } catch(e) {
            console.warn('GH.refresh:', e);
            _setRepoUI(cfg.repo, 'err');
            _showListMsg(`⚠ ${e.message}`);
        }
    }

    /* ── GitHub 사이드바 자동 새로고침 ─────────────────────
       연결 시 N초마다 HEAD SHA 확인 → 변경 시에만 refresh() (빠른 반응)
       ON/OFF·간격은 localStorage 유지. */
    const GH_AR_KEY = 'gh_auto_refresh';
    const GH_AR_INTERVAL_KEY = 'gh_ar_interval';
    function _getGhArInterval() { return Math.max(5, parseInt(localStorage.getItem(GH_AR_INTERVAL_KEY) || '15', 10) || 15); }
    let _ghArEnabled = localStorage.getItem(GH_AR_KEY) !== 'off';
    let _ghArTick = null;
    let _ghArCountdown = 0;
    let _ghLastHeadSha = null;  /* 마지막 알려진 HEAD 커밋 SHA (변경 감지용) */

    async function _ghGetHeadSha() {
        if (!cfg) return null;
        try {
            const refData = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
            return refData && refData.object ? refData.object.sha : null;
        } catch (e) { return null; }
    }

    function _ghArUpdateBtn() {
        const ids = ['gh-ar-btn', 'gh-ar-btn-modal'];
        const onClass = 'on';
        const offClass = 'off';
        ids.forEach(id => {
            const btn = document.getElementById(id);
            if (!btn) return;
            if (btn.classList.contains('gh-ar-btn-circle')) {
                btn.classList.remove(onClass, offClass);
                btn.classList.add(_ghArEnabled ? onClass : offClass);
            } else {
                btn.textContent = _ghArEnabled ? '🔄 ON' : '🔄 OFF';
                btn.style.color = _ghArEnabled ? '#6af7b0' : 'var(--tx3)';
                btn.style.borderColor = _ghArEnabled ? 'rgba(106,247,176,.35)' : 'var(--bd)';
                btn.style.background = _ghArEnabled ? 'rgba(106,247,176,.1)' : 'rgba(255,255,255,.04)';
            }
        });
    }

    function _ghArUpdateCountdown() {
        const ids = ['gh-ar-countdown', 'gh-ar-countdown-modal'];
        const text = _ghArEnabled && _ghArCountdown > 0 ? _ghArCountdown + 's' : '';
        const show = _ghArEnabled && _ghArCountdown > 0;
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = text;
            el.style.display = show ? 'inline' : 'none';
        });
    }

    function _ghStartAutoRefresh() {
        _ghStopAutoRefresh();
        if (!cfg || !_ghArEnabled) return;
        const intervalSec = _getGhArInterval();
        /* _ghLastHeadSha 없으면 첫 확인을 빠르게 (3초 후) */
        _ghArCountdown = _ghLastHeadSha ? intervalSec : Math.min(3, intervalSec);
        _ghArUpdateCountdown();

        _ghArTick = setInterval(async () => {
            _ghArCountdown--;
            _ghArUpdateCountdown();
            if (_ghArCountdown <= 0) {
                const currentSha = await _ghGetHeadSha();
                const needRefresh = !_ghLastHeadSha || (currentSha && currentSha !== _ghLastHeadSha);
                if (needRefresh) {
                    await refresh().catch(() => {});
                    _ghLastHeadSha = currentSha || await _ghGetHeadSha();
                }
                _ghArCountdown = _getGhArInterval();
            }
        }, 1000);
    }

    function _ghStopAutoRefresh() {
        if (_ghArTick) { clearInterval(_ghArTick); _ghArTick = null; }
        _ghArCountdown = 0;
        _ghArUpdateCountdown();
    }

    function toggleAutoRefresh() {
        _ghArEnabled = !_ghArEnabled;
        localStorage.setItem(GH_AR_KEY, _ghArEnabled ? 'on' : 'off');
        _ghArUpdateBtn();
        if (_ghArEnabled && cfg) {
            _ghStartAutoRefresh();
            App._toast('🔄 자동새로고침 ON (' + _getGhArInterval() + '초마다 GitHub 폴더)');
        } else {
            _ghStopAutoRefresh();
            App._toast('🔄 자동새로고침 OFF');
        }
    }

    function showArIntervalSetting() {
        const cur = _getGhArInterval();
        const v = prompt('자동 새로고침 간격 (초)\nGitHub 폴더 목록을 이 간격마다 갱신합니다.', String(cur));
        if (v == null) return;
        const num = parseInt(v, 10);
        if (!(num >= 5 && num <= 600)) {
            App._toast('⚠ 5~600 초 사이로 입력하세요');
            return;
        }
        localStorage.setItem(GH_AR_INTERVAL_KEY, String(num));
        if (_ghArEnabled && cfg) _ghStartAutoRefresh();
        App._toast('✅ 간격 ' + num + '초로 저장');
    }


    /* ── 검색 ─────────────────────────────────────────── */
    function search(q) {
        filtered = q
            ? allFiles.filter(f => f.name.toLowerCase().includes(q.toLowerCase())
                               || f.path.toLowerCase().includes(q.toLowerCase()))
            : allFiles;
        _render();
    }

    /* ── 렌더링 ───────────────────────────────────────── */
    function _render() {
        const list = document.getElementById('gh-list');
        if (!list) return;
        list.innerHTML = '';

        if (!cfg) {
            list.innerHTML =
                '<div class="files-empty">' +
                '<div style="font-size:26px;margin-bottom:8px">🐙</div>' +
                '<div style="font-weight:600;margin-bottom:6px">GitHub 저장소 연결</div>' +
                '<div style="color:var(--tx3);font-size:10px;line-height:1.7">' +
                '⚙ 설정 버튼을 눌러<br>Token + 저장소를 입력하세요</div>' +
                '</div>';
            return;
        }
        /* 파일이 없어도 빈 폴더(.gitkeep)가 있으면 렌더링 계속 */
        const hasEmptyFolders = Object.keys(_ghEmptyFolders).length > 0;
        if (!allFiles.length && !hasEmptyFolders) {
            list.innerHTML =
                '<div class="files-empty">' +
                '<div style="color:var(--tx3);font-size:11px">↻ 새로고침 버튼을 눌러<br>파일 목록을 불러오세요</div>' +
                '</div>';
            return;
        }

        const src = filtered;
        if (!src.length && !hasEmptyFolders) {
            list.innerHTML = '<div class="files-empty">검색 결과 없음</div>';
            return;
        }

        /* ── 트리 노드 빌드 ── */
        const root = { name: '', children: {}, files: [] };

        src.forEach(f => {
            const parts = f.path.split('/');
            let node = root;
            for (let i = 0; i < parts.length - 1; i++) {
                const seg = parts[i];
                if (!node.children[seg]) node.children[seg] = { name: seg, children: {}, files: [], _path: parts.slice(0, i+1).join('/') };
                node = node.children[seg];
            }
            node.files.push(f);
        });

        /* .gitkeep 기반 빈 폴더도 트리에 추가 */
        Object.keys(_ghEmptyFolders).sort().forEach(folderRel => {
            const base = cfg.basePath ? cfg.basePath.replace(/\/$/, '') + '/' : '';
            /* cfg.basePath가 있으면 그 아래 경로만 처리, 상위 경로는 스킵 */
            if (base && !folderRel.startsWith(base) && folderRel !== base.replace(/\/$/, '')) return;
            const relPath = base ? folderRel.slice(base.length) : folderRel;
            if (!relPath) return;
            const parts = relPath.split('/').filter(Boolean);
            let node = root;
            for (let i = 0; i < parts.length; i++) {
                const seg = parts[i];
                if (!node.children[seg]) {
                    node.children[seg] = {
                        name: seg, children: {}, files: [],
                        _path: parts.slice(0, i+1).join('/'),
                        _isEmpty: true
                    };
                }
                node = node.children[seg];
            }
        });

        function countFiles(node) {
            let n = node.files.length;
            Object.values(node.children).forEach(c => { n += countFiles(c); });
            return n;
        }

        function renderNode(node, depth, container) {
            const indent = depth * 12;

            Object.keys(node.children).sort().forEach(folderName => {
                const child = node.children[folderName];
                const total = countFiles(child);

                const folderEl = document.createElement('div');
                folderEl.className = 'ft-folder';

                const hdr = document.createElement('div');
                hdr.className = 'ft-folder-hdr';
                hdr.style.paddingLeft = (8 + indent) + 'px';
                const ghIsEmpty = (child._isEmpty && total === 0);
                hdr.innerHTML =
                    `<span class="ft-toggle">${ghIsEmpty ? '—' : '▾'}</span>` +
                    `<span class="ft-folder-icon">📂</span>` +
                    `<span class="ft-folder-name">${_esc(folderName)}</span>` +
                    `<span class="ft-count" style="${ghIsEmpty ? 'opacity:.4' : ''}">${ghIsEmpty ? '빈 폴더' : total}</span>` +
                    `<button class="fg-add-btn" title="이 폴더에 새 파일 만들기" ` +
                    `onclick="event.stopPropagation();GH._createFileInFolder('${_esc(child._path || folderName)}')">＋</button>` +
                    `<button class="folder-del-btn" title="${ghIsEmpty ? '빈 폴더 삭제' : '폴더 삭제 (내부 파일 포함)'}" ` +
                    `data-path="${_esc(child._path || folderName)}" data-empty="${ghIsEmpty}" ` +
                    `onclick="event.stopPropagation();GH.confirmDeleteFolder(this)">🗑</button>`;
                hdr.onclick = () => {
                    if (ghIsEmpty) return;
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

            node.files.forEach(f => {
                const row  = document.createElement('div');
                row.className = 'file-item' + (f.path === activeFile ? ' active' : '');
                row.dataset.ghPath = f.path;
                row.style.paddingLeft = (18 + indent) + 'px';
                const icon = f.ext === 'html' ? '🌐' : f.ext === 'txt' ? '📄' : '📝';
                const ghSizeStr = f.size != null
                    ? (f.size >= 1048576
                        ? (f.size / 1048576).toFixed(1) + 'MB'
                        : f.size >= 1024
                            ? (f.size / 1024).toFixed(1) + 'KB'
                            : f.size + 'B')
                    : '';
                const ghDateStr = f.date
                    ? new Date(f.date).toLocaleDateString('ko', { month:'2-digit', day:'2-digit' })
                    : '';
                const ghMeta = [ghSizeStr, ghDateStr].filter(Boolean).join(' · ');
                const ghMetaContent = ghSizeStr && ghDateStr
                    ? `<span class="file-item-meta-size">${ghSizeStr}</span> · <span class="file-item-meta-date">${ghDateStr}</span>`
                    : ghSizeStr ? `<span class="file-item-meta-size">${ghSizeStr}</span>` : ghDateStr ? `<span class="file-item-meta-date">${ghDateStr}</span>` : '';
                row.innerHTML =
                    `<span class="file-item-icon">${icon}</span>` +
                    `<span class="file-item-name">${_esc(f.name.replace(/\.[^.]+$/, ''))}</span>` +
                    `<span class="file-item-meta" data-gh-meta="${_esc(f.path)}">${ghMetaContent}</span>` +
                    `<button class="file-share-btn" title="md-viewer에 공개 Push" onclick="event.stopPropagation();GH.pushFile(this)">📤</button>` +
                    `<button class="file-move-btn" title="파일 이동" onclick="event.stopPropagation();GH.moveFile(this)">↗</button>` +
                    `<button class="file-del-btn" title="파일 삭제" onclick="event.stopPropagation();GH.confirmDelete(this)">🗑</button>`;
                row.title = f.path + (f.size != null ? '\n크기: ' + ghSizeStr : '') + (ghDateStr ? '\n수정: ' + ghDateStr : '');
                /* 날짜 없으면 lazy fetch */
                if (!f.date) _fetchFileDate(f);
                row._ghFile = f;
                row.onclick = () => _openFile(f);
                /* 터치 환경: 첫 탭=선택(버튼 표시), 두 번째 탭=파일 열기 */
                row.addEventListener('touchstart', function(ev) {
                    if (ev.target.closest('button')) return; // 버튼 직접 탭은 그냥 실행
                    const already = this.classList.contains('touch-sel');
                    // 다른 항목 선택 해제
                    document.querySelectorAll('.file-item.touch-sel').forEach(el => {
                        if (el !== this) el.classList.remove('touch-sel');
                    });
                    if (already) {
                        // 두 번째 탭 → 파일 열기
                        _openFile(f);
                        this.classList.remove('touch-sel');
                    } else {
                        // 첫 번째 탭 → 선택(버튼 표시)
                        this.classList.add('touch-sel');
                        ev.preventDefault(); // 클릭 이벤트 방지 (두 번 실행 방지)
                    }
                }, { passive: false });
                container.appendChild(row);
            });
        }

        renderNode(root, 0, list);
        /* 전체 접기 버튼: 렌더 후 기본은 모두 펼침 → ▽ */
        const foldBtn = document.getElementById('gh-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = '▽';
    }

    /* ── 전체 폴더 접기/펼치기 토글 (GitHub 트리) ───────── */
    function toggleFoldAll() {
        const list = document.getElementById('gh-list');
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
        const foldBtn = document.getElementById('gh-fold-toggle-btn');
        if (foldBtn) foldBtn.textContent = collapse ? '▾' : '▽';
    }

    /* ── GitHub 파일 삭제 확인 & 실행 ───────────────────── */
    function confirmDelete(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._ghFile;
        if (!f) return;
        DelConfirm.show({
            name : f.name,
            path : f.path,
            type : 'github',
            onConfirm: async (commitMsg) => {
                try {
                    /* SHA 조회 */
                    let sha = null;
                    const cached = _fileContentCache[f.path];
                    if (cached && cached.sha) {
                        sha = cached.sha;
                    } else {
                        const data = await _apiFetch(`/contents/${encodeURIComponent(f.path)}?ref=${cfg.branch}`);
                        sha = data.sha;
                    }
                    /* GitHub DELETE API */
                    await _apiFetch(`/contents/${encodeURIComponent(f.path)}`, {
                        method : 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body   : JSON.stringify({
                            message: commitMsg || `Delete ${f.name}`,
                            sha,
                            branch : cfg.branch || 'main',
                        }),
                    });
                    delete _fileContentCache[f.path];
                    allFiles = allFiles.filter(x => x.path !== f.path);
                    filtered = filtered.filter(x => x.path !== f.path);

                    /* 삭제 후 그 폴더에 파일이 없으면 → 빈 폴더로 표시
                       (GitHub에 .gitkeep이 있으므로 폴더 자체는 존재) */
                    const deletedFolder = f.path.includes('/')
                        ? f.path.split('/').slice(0, -1).join('/')
                        : null;
                    if (deletedFolder) {
                        const stillHasFiles = allFiles.some(x =>
                            x.path.startsWith(deletedFolder + '/') || x.folder === deletedFolder
                        );
                        if (!stillHasFiles) {
                            _ghEmptyFolders[deletedFolder] = true;
                            /* IDB도 갱신 */
                            _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) }).catch(()=>{});
                        }
                    }

                    _render();
                    App._toast(`🗑 ${f.name} 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    /* ── gh-list에서 해당 path 하이라이트 및 스크롤 (탭 선택 또는 파일 클릭 시) ── */
    function _highlightFileInList(path) {
        const list = document.getElementById('gh-list');
        if (!list) return;
        list.querySelectorAll('.file-item').forEach(el => {
            el.classList.toggle('active', el.dataset.ghPath === path);
        });
        const activeRow = list.querySelector('.file-item.active');
        if (activeRow) activeRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    /* ── 활성 탭에 맞춰 gh-list 하이라이트 동기화 (탭 선택 시 호출) ── */
    function syncHighlightFromActiveTab() {
        const tab = typeof TM !== 'undefined' ? TM.getActive() : null;
        const path = tab && tab.ghPath ? tab.ghPath : null;
        activeFile = path;
        _highlightFileInList(path);
    }

    /* ── 파일 열기 ────────────────────────────────────── */
    async function _openFile(f) {
        activeFile = f.path;
        _highlightFileInList(f.path);

        /* 세션 캐시 확인 */
        if (_fileContentCache[f.path]) {
            _openInEditor(f, _fileContentCache[f.path].content);
            return;
        }

        /* API에서 내용 가져오기 */
        try {
            _showListMsg(`⟳ ${f.name} 불러오는 중…`);
            const data = await _apiFetch(`/contents/${encodeURIComponent(f.path)}?ref=${cfg.branch}`);
            /* GitHub API는 Base64로 반환 */
            const content = decodeURIComponent(escape(atob(data.content.replace(/\n/g,''))));
            _fileContentCache[f.path] = { content, sha: data.sha };
            /* SHA 업데이트 (저장 시 필요) */
            f.sha = data.sha;
            _render(); // 로딩 메시지 제거
            _openInEditor(f, content);
        } catch(e) {
            _render();
            alert(`파일을 불러올 수 없습니다:\n${e.message}`);
        }
    }

    function _openInEditor(f, rawContent) {
        const name    = f.name.replace(/\.[^.]+$/, '');
        const ft      = f.ext === 'html' ? 'md' : f.ext;
        const content = f.ext === 'html'
            ? (TM._htmlToEditableContent || (x=>x))(rawContent)
            : rawContent;

        const existing = TM.getAll().find(t => t.ghPath === f.path || t.title === name);
        if (existing) { TM.switchTab(existing.id); return; }

        const tab = TM.newTab(name, content, ft);
        tab.ghPath  = f.path;
        tab.ghSha   = f.sha;
        tab.ghBranch = cfg.branch;
        TM.markClean(tab.id);
        TM.renderTabs();
        TM.persist();
    }

    /* ── GitHub에 저장 (PUT) ──────────────────────────── */
    async function saveFile(tabId, commitMsg) {
        if (!cfg) { alert('GitHub 연결이 설정되지 않았습니다'); return false; }
        const tab = TM.getAll().find(t => t.id === tabId);
        if (!tab || !tab.ghPath) { alert('이 파일은 GitHub에서 열지 않았습니다'); return false; }

        const fileContent = document.getElementById('editor').value;
        const b64 = btoa(unescape(encodeURIComponent(fileContent)));
        const msg = commitMsg || `Update ${tab.title}`;

        try {
            /* SHA가 없으면 먼저 API에서 현재 SHA 조회
               (새 파일 생성 직후 SHA 누락 or 다른 기기에서 수정된 경우 대비) */
            if (!tab.ghSha) {
                try {
                    const info = await _apiFetch(
                        `/contents/${tab.ghPath}?ref=${tab.ghBranch || cfg.branch}`
                    );
                    if (info && info.sha) tab.ghSha = info.sha;
                } catch(e2) {
                    /* 파일이 아직 없으면(404) SHA 없이 신규 생성으로 진행 */
                    if (!e2.message.includes('404')) throw e2;
                }
            }

            const body = {
                message: msg,
                content: b64,
                branch : tab.ghBranch || cfg.branch,
            };
            if (tab.ghSha) body.sha = tab.ghSha;

            const res = await _apiFetch(`/contents/${tab.ghPath}`, {
                method : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify(body),
            });

            /* 새 SHA 저장 */
            tab.ghSha = res.content.sha;
            _fileContentCache[tab.ghPath] = { content: fileContent, sha: res.content.sha };
            TM.markClean(tabId);
            TM.renderTabs();
            return true;
        } catch(e) {
            alert(`GitHub 저장 실패:\n${e.message}`);
            return false;
        }
    }

    /* ── 새 파일 생성 ─────────────────────────────────── */
    async function createFile(path, content, commitMsg) {
        if (!cfg) { alert('GitHub 연결 필요'); return false; }
        const b64 = btoa(unescape(encodeURIComponent(content)));
        try {
            await _apiFetch(`/contents/${encodeURIComponent(path)}`, {
                method : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    message: commitMsg || `Create ${path}`,
                    content: b64,
                    branch : cfg.branch,
                }),
            });
            await refresh();
            return true;
        } catch(e) {
            alert(`파일 생성 실패:\n${e.message}`);
            return false;
        }
    }

    /* ── UI 헬퍼 ──────────────────────────────────────── */
    function _setRepoUI(repoName, state) {
        const nameEl    = document.getElementById('gh-repo-name');
        const refBtn    = document.getElementById('gh-refresh-btn');
        const cloneBtn  = document.getElementById('gh-clone-btn');
        const linkEl    = document.getElementById('gh-repo-link');
        const quickBtn  = document.getElementById('gh-quick-connect-btn');
        const connected = !!cfg;

        if (nameEl) {
            if (state === 'loading') { nameEl.textContent = '⟳ 로딩 중…'; nameEl.style.color = 'var(--tx3)'; }
            else if (state === 'err') { nameEl.textContent = `⚠ ${repoName}`; nameEl.style.color = '#f76a6a'; }
            else if (connected) {
                nameEl.textContent = cfg.repo.split('/').pop() + (allFiles.length ? ` (${allFiles.length})` : '');
                nameEl.style.color = 'var(--tx2)';
            } else {
                nameEl.textContent = '미연결';
                nameEl.style.color = 'var(--tx3)';
            }
        }
        /* 연결 상태에 따라 버튼 표시/숨김 */
        if (refBtn)   refBtn.style.display   = connected ? '' : 'none';
        if (cloneBtn) cloneBtn.style.display  = connected ? '' : 'none';
                if (quickBtn) quickBtn.style.display  = connected ? 'none' : '';
        const saveBtn = document.getElementById('gh-hdr-save-btn');
        if (saveBtn) {
            if (connected) saveBtn.classList.add('gh-hdr-save-connected');
            else saveBtn.classList.remove('gh-hdr-save-connected');
        }
        if (linkEl && connected) {
            linkEl.href         = 'https://github.com/' + cfg.repo;
            linkEl.style.display = '';
        } else if (linkEl) {
            linkEl.style.display = 'none';
        }
        /* 새파일/새폴더 버튼: 연결 시에만 표시 (sb-stats 한 줄) */
        const ghNewfileBtn = document.getElementById('gh-newfile-btn');
        const ghMkdirBtn = document.getElementById('gh-mkdir-btn');
        if (ghNewfileBtn) ghNewfileBtn.style.display = connected ? '' : 'none';
        if (ghMkdirBtn) ghMkdirBtn.style.display = connected ? '' : 'none';
        if (connected) {
            _ghArUpdateBtn();
            if (_ghArEnabled) _ghStartAutoRefresh();
        } else {
            _ghStopAutoRefresh();
        }
        /* 스테이터스바 자동새로고침 영역: 연결 시에만 표시 */
        const sbArWrap = document.getElementById('statusbar-ar-wrap');
        const sbArSep = document.getElementById('statusbar-ar-sep');
        if (sbArWrap) sbArWrap.style.display = connected ? 'flex' : 'none';
        if (sbArSep) sbArSep.style.display = connected ? '' : 'none';
        /* 연결된 repo URL 배너 업데이트 */
        let urlBanner = document.getElementById('gh-url-banner');
        if (!urlBanner) {
            urlBanner = document.createElement('div');
            urlBanner.id = 'gh-url-banner';
            const ghHdr = document.getElementById('gh-hdr');
            if (ghHdr && ghHdr.parentNode) ghHdr.parentNode.insertBefore(urlBanner, ghHdr.nextSibling);
        }
        if (connected && cfg.repo) {
            const branch = cfg.branch || 'main';
            const pathInfo = cfg.path ? ' / ' + cfg.path : '';
            urlBanner.innerHTML = '<a href="https://github.com/' + cfg.repo + '" target="_blank" title="GitHub 저장소 열기">🔗 github.com/' + cfg.repo + '</a><span class="gh-url-branch">' + branch + pathInfo + '</span>';
            urlBanner.style.display = '';
        } else {
            urlBanner.style.display = 'none';
        }
    
    }

    function _showListMsg(msg) {
        const list = document.getElementById('gh-list');
        if (list) list.innerHTML = `<div class="files-empty" style="padding-top:20px">${_esc(msg)}</div>`;
    }

    function _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    /* ── 빠른 연결 테스트 (연결 테스트&저장 버튼) ─────────── */
    async function quickConnect() {
        if (!cfg || !cfg.token || !cfg.repo) {
            /* 설정 미완료 → 설정 모달 열기 */
            const ok = confirm(
                'GitHub 연결 설정이 필요합니다.\n\n' +
                '설정 창에서 Token과 저장소를 입력한 후\n' +
                '"연결 테스트 & 저장" 버튼을 눌러주세요.\n\n' +
                '지금 설정 창을 여시겠습니까?'
            );
            if (ok) showSettings();
            return;
        }
        /* 설정 완료 → 즉시 연결 테스트 */
        const btn = document.getElementById('gh-quick-connect-btn');
        if (btn) { btn.textContent = '연결 중…'; btn.disabled = true; }
        try {
            /* 저장소 정보 조회로 연결 확인 */
            const data = await _apiFetch('');   /* /repos/owner/repo */
            App._toast('✓ GitHub 연결 성공: ' + data.full_name);
            /* 파일 목록 로드 */
            await refresh();
        } catch(e) {
            const msg = e.message || '알 수 없는 오류';
            if (msg.includes('401')) {
                alert('❌ 인증 실패\nToken이 올바르지 않습니다.\n설정을 확인하세요.');
            } else if (msg.includes('404')) {
                alert('❌ 저장소 없음\n저장소 주소를 확인하세요: ' + cfg.repo);
            } else {
                alert('❌ 연결 실패: ' + msg);
            }
        } finally {
            if (btn) { btn.textContent = '연결 테스트 & 저장'; btn.disabled = false; }
        }
    }

    function isConnected() { return !!cfg; }

    /* ── 로컬 파일 목록 → GitHub 일괄 push ──────────────
       Git Data API 흐름:
       1. 현재 branch HEAD SHA 취득
       2. 변경/신규 파일 → Blob API로 각각 업로드 (SHA 취득)
       3. Base tree + 새 항목으로 Tree 생성
       4. 새 Commit 생성 (parent = HEAD)
       5. branch ref를 새 commit SHA로 업데이트            */
    async function pushLocalFiles(files, commitMsg) {
        /* files: [{path, content}]  path = GitHub repo 내 경로 */
        if (!cfg) throw new Error('GitHub 설정이 없습니다');
        if (!files.length) return { pushed: 0 };

        /* 1. HEAD commit SHA + base tree SHA */
        const refData  = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
        const headSHA  = refData.object.sha;
        const commitData = await _apiFetch(`/git/commits/${headSHA}`);
        const baseTree = commitData.tree.sha;

        /* 2. 각 파일을 Blob으로 업로드 */
        const treeItems = await Promise.all(files.map(async f => {
            const blob = await _apiFetch('/git/blobs', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    content : btoa(unescape(encodeURIComponent(f.content))),
                    encoding: 'base64',
                }),
            });
            return { path: f.path, mode: '100644', type: 'blob', sha: blob.sha };
        }));

        /* 3. 새 Tree 생성 */
        const newTree = await _apiFetch('/git/trees', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ base_tree: baseTree, tree: treeItems }),
        });

        /* 4. 새 Commit 생성 */
        const newCommit = await _apiFetch('/git/commits', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                message: commitMsg,
                tree   : newTree.sha,
                parents: [headSHA],
            }),
        });

        /* 5. branch ref 업데이트 (fast-forward) */
        await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
            method : 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ sha: newCommit.sha }),
        });

        /* GH 파일 목록 캐시 무효화 → 다음 렌더 시 새로고침 */
        await _ghClear('files');
        allFiles = [];

        return { pushed: files.length, commitSha: newCommit.sha.slice(0,7) };
    }

    /* GitHub 현재 파일 SHA 맵 취득 (변경 감지용) */
    async function getRemoteSHAs() {
        if (!cfg) return {};
        try {
            const tree = await _apiFetch(`/git/trees/${cfg.branch}?recursive=1`);
            const map = {};
            const base = cfg.basePath ? cfg.basePath + '/' : '';
            tree.tree.forEach(item => {
                if (item.type === 'blob') map[item.path] = item.sha;
            });
            return map;
        } catch(e) { return {}; }
    }

    /* ── 빠른 연결 테스트 (연결 테스트&저장 버튼) ─────────── */
    async function quickConnect() {
        if (!cfg || !cfg.token || !cfg.repo) {
            /* 설정 미완료 → 설정 모달 열기 */
            const ok = confirm(
                'GitHub 연결 설정이 필요합니다.\n\n' +
                '설정 창에서 Token과 저장소를 입력한 후\n' +
                '"연결 테스트 & 저장" 버튼을 눌러주세요.\n\n' +
                '지금 설정 창을 여시겠습니까?'
            );
            if (ok) showSettings();
            return;
        }
        /* 설정 완료 → 즉시 연결 테스트 */
        const btn = document.getElementById('gh-quick-connect-btn');
        if (btn) { btn.textContent = '연결 중…'; btn.disabled = true; }
        try {
            /* 저장소 정보 조회로 연결 확인 */
            const data = await _apiFetch('');   /* /repos/owner/repo */
            App._toast('✓ GitHub 연결 성공: ' + data.full_name);
            /* 파일 목록 로드 */
            await refresh();
        } catch(e) {
            const msg = e.message || '알 수 없는 오류';
            if (msg.includes('401')) {
                alert('❌ 인증 실패\nToken이 올바르지 않습니다.\n설정을 확인하세요.');
            } else if (msg.includes('404')) {
                alert('❌ 저장소 없음\n저장소 주소를 확인하세요: ' + cfg.repo);
            } else {
                alert('❌ 연결 실패: ' + msg);
            }
        } finally {
            if (btn) { btn.textContent = '연결 테스트 & 저장'; btn.disabled = false; }
        }
    }

    function isConnected() { return !!cfg; }

    /* ── 저장 모달용 폴더 목록 (위치 드롭다운) ─────────────
       currentFolder: 현재 선택할 폴더 (옵션에 없으면 추가) */
    function getFolderOptionsForSave(currentFolder) {
        const folderSet = new Set(['/']);
        const base = cfg && cfg.basePath ? cfg.basePath.replace(/\/$/, '') + '/' : '';
        allFiles.forEach(f => {
            const p = base && f.path.startsWith(base) ? f.path.slice(base.length) : f.path;
            const parts = p.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => {
            if (fp && (!base || fp.startsWith(base))) {
                const rel = base ? fp.slice(base.length) : fp;
                if (rel) folderSet.add(rel);
            }
        });
        if (currentFolder && currentFolder !== '/') folderSet.add(currentFolder);
        return [...folderSet].sort().map(p =>
            `<option value="${p}">${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');
    }

    /* ── 저장소 링크 열기 ─────────────────────────────── */
    function openRepoLink() {
        if (!cfg) return;
        window.open(`https://github.com/${cfg.repo}`, '_blank');
    }

    /* ── Clone: 저장소 전체를 IDB 캐시에 다운로드 ────────
       실제 git clone과 동일한 효과.
       이미 restore()/refresh()가 이 역할을 하므로
       refresh()를 호출하고 _baseSHAs를 초기화           */
    async function cloneRepo() {
        if (!cfg) { showSettings(); return; }
        const ok = confirm(
            `저장소 전체를 다운로드합니다.

` +
            `${cfg.repo}  (${cfg.branch} 브랜치)

` +
            `기존 캐시는 교체됩니다. 계속하시겠습니까?`
        );
        if (!ok) return;
        /* baseSHAs 초기화 → 다음 push 때 모든 파일이 new-local로 분류되지 않도록
           clone 직후 원격 SHA를 기준점으로 설정해야 함 → refresh 후 처리        */
        await refresh();
        /* refresh 완료 후 원격 SHA를 기준점으로 저장 → FM에 알림 */
        if (typeof FM !== 'undefined') {
            const remote = await getRemoteSHAs();
            FM._setBaseSHAsFromRemote(remote, cfg.basePath || '');
        }
    }

    /* ── 파일명 변경 커밋 (rename = delete old + create new) ──
       Git Data API로 단일 커밋에 처리.
       ※ oldPath가 base tree에 없으면 삭제 항목 제외 (422 BadObjectState 방지)  */
    async function renameAndCommit(oldPath, newPath, content, commitMsg) {
        if (!cfg) throw new Error('GitHub 설정 없음');

        /* HEAD 및 base tree 조회 */
        const refData    = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
        const headSHA    = refData.object.sha;
        const commitData = await _apiFetch(`/git/commits/${headSHA}`);
        const baseTree   = commitData.tree.sha;

        /* oldPath 존재 여부 확인 (없으면 sha:null 삭제 시 422 BadObjectState 발생) */
        let oldPathExists = false;
        try {
            await _apiFetch(`/contents/${encodeURIComponent(oldPath)}?ref=${cfg.branch}`);
            oldPathExists = true;
        } catch (e) {
            if (!e.message || !e.message.includes('404')) throw e;
        }

        /* 새 파일 Blob 생성 */
        const blob = await _apiFetch('/git/blobs', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                content : btoa(unescape(encodeURIComponent(content))),
                encoding: 'base64',
            }),
        });

        /* Tree: oldPath 존재 시에만 삭제(null) + 새 경로 추가 */
        const treeItems = [];
        if (oldPathExists && oldPath !== newPath) {
            treeItems.push({ path: oldPath, mode: '100644', type: 'blob', sha: null });
        }
        treeItems.push({ path: newPath, mode: '100644', type: 'blob', sha: blob.sha });

        let newTree;
        try {
            newTree = await _apiFetch('/git/trees', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({ base_tree: baseTree, tree: treeItems }),
            });
        } catch (e) {
            /* 422 BadObjectState 등: Contents API로 폴백 (1~2커밋) */
            if (e.message && (e.message.includes('422') || e.message.includes('BadObjectState'))) {
                let oldSha = null;
                try {
                    const oldInfo = await _apiFetch(`/contents/${encodeURIComponent(oldPath)}?ref=${cfg.branch}`);
                    if (oldInfo && oldInfo.sha) oldSha = oldInfo.sha;
                } catch (_) {}
                if (oldSha) {
                    await _apiFetch(`/contents/${encodeURIComponent(oldPath)}`, {
                        method : 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body   : JSON.stringify({ message: commitMsg || 'Rename', branch: cfg.branch, sha: oldSha }),
                    });
                }
                await _apiFetch(`/contents/${encodeURIComponent(newPath)}`, {
                    method : 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({
                        message: commitMsg || `Rename ${oldPath} → ${newPath}`,
                        content: btoa(unescape(encodeURIComponent(content))),
                        branch : cfg.branch,
                    }),
                });
                await refresh();
                return { commitSha: 'ok' };
            }
            throw e;
        }

        const newCommit = await _apiFetch('/git/commits', {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({
                message: commitMsg || `Rename ${oldPath.split('/').pop()} → ${newPath.split('/').pop()}`,
                tree   : newTree.sha,
                parents: [headSHA],
            }),
        });

        await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
            method : 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body   : JSON.stringify({ sha: newCommit.sha }),
        });

        /* 캐시 무효화 */
        await _ghClear('files');
        allFiles = [];

        return { commitSha: newCommit.sha.slice(0, 7) };
    }

    /* ── 새 커밋 알람: 앱 시작 시 HEAD 비교 ──────────────
       localStorage에 마지막으로 본 commitSHA 저장
       앱 열 때 현재 HEAD와 비교 → 새 커밋이면 배너 표시  */
    const SEEN_SHA_KEY = 'mdpro_gh_seen_sha';

    async function checkNewCommits() {
        if (!cfg) return;
        try {
            const refData = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
            const currentSHA = refData.object.sha;
            const seenSHA    = localStorage.getItem(SEEN_SHA_KEY + '_' + cfg.repo);

            if (!seenSHA) {
                /* 첫 실행: 현재 SHA를 기준으로 저장 */
                localStorage.setItem(SEEN_SHA_KEY + '_' + cfg.repo, currentSHA);
                return;
            }
            if (seenSHA === currentSHA) return; // 변경 없음

            /* 새 커밋 수 계산 */
            const compareData = await _apiFetch(
                `/compare/${seenSHA}...${currentSHA}`
            );
            const newCount  = compareData.ahead_by || 0;
            const commits   = compareData.commits  || [];
            const lastAuthor = commits.length
                ? commits[commits.length - 1].commit.author.name
                : '알 수 없음';

            _showCommitBanner(newCount, lastAuthor, currentSHA, commits);
        } catch(e) {
            console.warn('GH.checkNewCommits:', e);
        }
    }

    function _showCommitBanner(count, author, sha, commits) {
        const banner  = document.getElementById('gh-new-commits-banner');
        const msgEl   = document.getElementById('gh-new-commits-msg');
        if (!banner || !msgEl) return;
        msgEl.innerHTML =
            `🔔 <b>${count}개</b>의 새 커밋 ` +
            `— 마지막: <b>${_esc(author)}</b> ` +
            `<a href="https://github.com/${cfg.repo}/commits/${cfg.branch}" ` +
            `target="_blank" style="color:var(--ac);text-decoration:none">` +
            `커밋 보기 →</a>`;
        banner.style.display = '';
        banner._currentSHA = sha;
    }

    function dismissCommitBanner() {
        const banner = document.getElementById('gh-new-commits-banner');
        if (!banner) return;
        if (banner._currentSHA && cfg) {
            localStorage.setItem(SEEN_SHA_KEY + '_' + cfg.repo, banner._currentSHA);
        }
        banner.style.display = 'none';
    }

    /* ── 기기 활동 표시 ───────────────────────────────────
       최근 커밋의 committer name에서 기기명 파싱
       커밋 메시지 형식: "Update file [device:MacBook Pro]"
       이 형식으로 저장하면 기기별 활동 추적 가능         */
    async function loadDeviceActivity() {
        if (!cfg) return;
        try {
            const commits = await _apiFetch(`/commits?sha=${cfg.branch}&per_page=10`);
            const deviceSet = new Set();
            commits.forEach(c => {
                const m = c.commit.message.match(/\[device:([^\]]+)\]/);
                if (m) deviceSet.add(m[1]);
            });
            const bar  = document.getElementById('gh-device-bar');
            const info = document.getElementById('gh-device-info');
            if (!bar || !info) return;
            if (deviceSet.size) {
                info.textContent = `최근 기기: ${[...deviceSet].join(', ')}`;
                bar.style.display = '';
            }
        } catch(e) {}
    }

    /* ── _setRepoUI 확장: 링크 버튼 표시 ────────────────── */
    function _setRepoUI(repoName, state) {
        const nameEl   = document.getElementById('gh-repo-name');
        const refBtn   = document.getElementById('gh-refresh-btn');
        const cloneBtn = document.getElementById('gh-clone-btn');
        const linkBtn  = document.getElementById('gh-repo-link');
        const connected = !!cfg;
        if (nameEl) {
            if (state === 'loading') { nameEl.textContent = '⟳ 로딩 중…'; nameEl.style.color = 'var(--tx3)'; }
            else if (state === 'err') { nameEl.textContent = `⚠ ${repoName}`; nameEl.style.color = '#f76a6a'; }
            else if (connected) { nameEl.textContent = repoName + (allFiles.length ? `  (${allFiles.length}개)` : ''); nameEl.style.color = 'var(--tx2)'; }
            else { nameEl.textContent = '미연결'; nameEl.style.color = 'var(--tx3)'; }
        }
        if (refBtn)   refBtn.style.display   = connected ? '' : 'none';
        if (cloneBtn) cloneBtn.style.display  = connected ? '' : 'none';
        const saveBtn = document.getElementById('gh-hdr-save-btn');
        if (saveBtn) {
            if (connected) saveBtn.classList.add('gh-hdr-save-connected');
            else saveBtn.classList.remove('gh-hdr-save-connected');
        }
        if (linkBtn && connected) {
            linkBtn.href = `https://github.com/${cfg.repo}`;
            linkBtn.style.display = '';
        } else if (linkBtn) {
            linkBtn.style.display = 'none';
        }
        /* 새파일/새폴더 버튼: 연결 시에만 표시 (sb-stats 한 줄) */
        const ghNewfileBtn = document.getElementById('gh-newfile-btn');
        const ghMkdirBtn = document.getElementById('gh-mkdir-btn');
        if (ghNewfileBtn) ghNewfileBtn.style.display = connected ? '' : 'none';
        if (ghMkdirBtn) ghMkdirBtn.style.display = connected ? '' : 'none';
        if (connected) {
            _ghArUpdateBtn();
            if (_ghArEnabled) _ghStartAutoRefresh();
        } else {
            _ghStopAutoRefresh();
        }
        const sbArWrap = document.getElementById('statusbar-ar-wrap');
        const sbArSep = document.getElementById('statusbar-ar-sep');
        if (sbArWrap) sbArWrap.style.display = connected ? 'flex' : 'none';
        if (sbArSep) sbArSep.style.display = connected ? '' : 'none';
        const ghCommitBtn = document.getElementById('gh-commit-history-btn');
        if (ghCommitBtn) ghCommitBtn.style.display = connected ? '' : 'none';
    }

    /* ── 커밋 히스토리 (GHHistory 위임) ───────────────────────────────── */
    async function loadHistory(forceRefresh) {
        if (!cfg) { alert('GitHub 연결 필요'); return; }
        if (typeof GHHistory !== 'undefined') return GHHistory.loadHistory(cfg, forceRefresh);
    }
    function refreshHistory() { if (typeof GHHistory !== 'undefined') GHHistory.refreshHistory(cfg); }
    function filterHistory(q) { if (typeof GHHistory !== 'undefined') GHHistory.filterHistory(q); }

    /* ── 빠른 연결 테스트 (연결 테스트&저장 버튼) ─────────── */
    async function quickConnect() {
        if (!cfg || !cfg.token || !cfg.repo) {
            /* 설정 미완료 → 설정 모달 열기 */
            const ok = confirm(
                'GitHub 연결 설정이 필요합니다.\n\n' +
                '설정 창에서 Token과 저장소를 입력한 후\n' +
                '"연결 테스트 & 저장" 버튼을 눌러주세요.\n\n' +
                '지금 설정 창을 여시겠습니까?'
            );
            if (ok) showSettings();
            return;
        }
        /* 설정 완료 → 즉시 연결 테스트 */
        const btn = document.getElementById('gh-quick-connect-btn');
        if (btn) { btn.textContent = '연결 중…'; btn.disabled = true; }
        try {
            /* 저장소 정보 조회로 연결 확인 */
            const data = await _apiFetch('');   /* /repos/owner/repo */
            App._toast('✓ GitHub 연결 성공: ' + data.full_name);
            /* 파일 목록 로드 */
            await refresh();
        } catch(e) {
            const msg = e.message || '알 수 없는 오류';
            if (msg.includes('401')) {
                alert('❌ 인증 실패\nToken이 올바르지 않습니다.\n설정을 확인하세요.');
            } else if (msg.includes('404')) {
                alert('❌ 저장소 없음\n저장소 주소를 확인하세요: ' + cfg.repo);
            } else {
                alert('❌ 연결 실패: ' + msg);
            }
        } finally {
            if (btn) { btn.textContent = '연결 테스트 & 저장'; btn.disabled = false; }
        }
    }

    function isConnected() { return !!cfg; }

    /* ── GitHub에 새 파일 만들기 ──────────────────────── */
    /* ── GitHub 새 파일 만들기 ─────────────────────────
       흐름: 에디터에 빈 파일 열기 → 저장 시 자동 GitHub Push
       (GitHub Contents API는 특정 경로가 없으면 404 반환하므로
        파일 내용을 직접 PUT 하는 방식으로 변경)
    ──────────────────────────────────────────────── */
    async function createNewFile() {
        if (!cfg) { alert('GitHub 연결 필요'); return; }

        /* 현재 저장소 내 폴더 목록 구성 (파일 경로 + 빈 폴더 포함) */
        const folderSet = new Set(['/']);
        allFiles.forEach(f => {
            const parts = f.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });
        const folderOptions = [...folderSet].sort().map(p =>
            `<option value="${p}">${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');

        /* 모달 */
        const result = await _ghNewItemModal({
            title: '📄 GitHub 새 파일',
            folderOptions,
            namePlaceholder: 'notes.md',
            nameLabel: '파일 이름 (.md 자동 추가)',
            okLabel: '✔ 에디터에서 열기 & Push',
        });
        if (!result) return;

        let fname = result.name.trim();
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[\\:*?"<>|]/g, '_');
        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const folderPart = result.folder && result.folder !== '/' ? result.folder + '/' : '';
        const filePath = basePath + folderPart + safe;

        /* 에디터에 새 탭으로 열고 ghPath 지정 → 저장 시 자동 Push */
        const title = safe.replace(/\.[^.]+$/, '');
        const initContent = '# ' + title + '\n\n';
        const tab = TM.newTab(title, initContent, 'md');
        tab.ghPath   = filePath;
        tab.ghBranch = cfg.branch || 'main';
        TM.markDirty();
        TM.renderTabs();

        /* 즉시 GitHub에 빈 파일 Push — 응답 SHA를 tab에 저장해야 다음 저장 시 422 방지 */
        try {
            App._toast('⟳ GitHub에 파일 생성 중…');
            const encoded = btoa(unescape(encodeURIComponent(initContent)));
            const res = await _apiFetch(`/contents/${filePath}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: 'Create ' + safe,
                    content: encoded,
                    branch: cfg.branch || 'main',
                }),
            });
            /* ★ SHA 저장 — 없으면 다음 PUT 때 422 "sha wasn't supplied" 오류 */
            if (res && res.content && res.content.sha) {
                tab.ghSha = res.content.sha;
                _fileContentCache[filePath] = { content: initContent, sha: res.content.sha };
            }
            TM.markClean(tab.id);
            TM.renderTabs();
            App._toast('✅ ' + safe + ' 생성 & Push 완료');
            await refresh();
        } catch(e) {
            App._toast('⚠ 파일은 열렸으나 Push 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 새 폴더 만들기 ───────────────────────────
       Git은 빈 폴더를 추적하지 않으므로
       폴더/.gitkeep 파일을 Push해서 폴더를 생성합니다.
    ──────────────────────────────────────────────── */
    async function createNewFolder() {
        if (!cfg) { alert('GitHub 연결 필요'); return; }

        const folderSet = new Set(['/']);
        allFiles.forEach(f => {
            const parts = f.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });
        const folderOptions = [...folderSet].sort().map(p =>
            `<option value="${p}">${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');

        const result = await _ghNewItemModal({
            title: '📁 GitHub 새 폴더',
            folderOptions,
            namePlaceholder: '새폴더',
            nameLabel: '폴더 이름',
            okLabel: '✔ 생성 & Push',
            isFolder: true,
        });
        if (!result) return;

        const safe = result.name.trim().replace(/[/\\:*?"<>|]/g, '_');
        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const folderPart = result.folder && result.folder !== '/' ? result.folder + '/' : '';
        const keepPath = basePath + folderPart + safe + '/.gitkeep';

        try {
            App._toast('⟳ GitHub에 폴더 생성 중…');
            await _apiFetch(`/contents/${keepPath}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: 'Create folder ' + safe,
                    content: btoa(''),
                    branch: cfg.branch || 'main',
                }),
            });
            App._toast('✅ ' + safe + ' 폴더 생성 & Push 완료');
            await refresh();
        } catch(e) {
            alert('폴더 생성 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 새 파일/폴더 생성 공용 모달 ─────────────── */
    function _ghNewItemModal({ title, folderOptions, namePlaceholder, nameLabel, okLabel, isFolder }) {
        return new Promise(resolve => {
            const existing = document.getElementById('gh-newitem-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'gh-newitem-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:340px;max-width:460px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">${title}</span>
                    <button id="gni-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (폴더)</label>
                    <select id="gni-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions}
                    </select>
                </div>
                <div style="margin-bottom:${isFolder ? 8 : 16}px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">${nameLabel}</label>
                    <input id="gni-name" type="text" placeholder="${namePlaceholder}"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                ${!isFolder ? `
                <div style="margin-bottom:16px;padding:9px 12px;background:rgba(124,106,247,.08);border:1px solid rgba(124,106,247,.25);border-radius:7px;font-size:11px;color:var(--tx2);line-height:1.7">
                    💡 파일이 에디터에 열리고 <b>GitHub에 즉시 Push</b>됩니다.<br>
                    이후 수정 내용은 <b>저장(💾) → GitHub 커밋</b>으로 반영하세요.
                </div>` : `
                <div style="margin-bottom:16px;padding:9px 12px;background:rgba(124,106,247,.08);border:1px solid rgba(124,106,247,.25);border-radius:7px;font-size:11px;color:var(--tx2);line-height:1.7">
                    💡 Git은 빈 폴더를 저장할 수 없어 <b>.gitkeep</b> 파일이 함께 Push됩니다.
                </div>`}
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="gni-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="gni-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">${okLabel}</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('gni-name');
            setTimeout(() => { nameInput.focus(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('gni-close').onclick = () => close(null);
            document.getElementById('gni-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('gni-ok').onclick = () => {
                const n = nameInput.value.trim();
                if (!n) { nameInput.focus(); return; }
                close({ folder: document.getElementById('gni-folder').value, name: n });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('gni-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 파일별 마지막 커밋 날짜 lazy fetch ─────────────── */
    const _dateFetchQueue = new Set();
    async function _fetchFileDate(f) {
        if (_dateFetchQueue.has(f.path)) return;
        _dateFetchQueue.add(f.path);
        try {
            const commits = await _apiFetch(
                `/commits?path=${encodeURIComponent(f.path)}&sha=${cfg.branch || 'main'}&per_page=1`
            );
            if (commits && commits.length > 0) {
                f.date = commits[0].commit.author.date;
                /* DOM 업데이트 — 해당 파일의 meta span만 */
                const span = document.querySelector(`.file-item-meta[data-gh-meta="${CSS.escape(f.path)}"]`);
                if (span) {
                    const ghSizeStr = f.size != null
                        ? (f.size >= 1048576
                            ? (f.size / 1048576).toFixed(1) + 'MB'
                            : f.size >= 1024
                                ? (f.size / 1024).toFixed(1) + 'KB'
                                : f.size + 'B')
                        : '';
                    const ghDateStr = new Date(f.date).toLocaleDateString('ko', { month:'2-digit', day:'2-digit' });
                    span.innerHTML = ghSizeStr && ghDateStr
                        ? `<span class="file-item-meta-size">${ghSizeStr}</span> · <span class="file-item-meta-date">${ghDateStr}</span>`
                        : ghSizeStr ? `<span class="file-item-meta-size">${ghSizeStr}</span>` : ghDateStr ? `<span class="file-item-meta-date">${ghDateStr}</span>` : '';
                    const row = span.closest('.file-item');
                    if (row) row.title = f.path + (ghSizeStr ? '\n크기: ' + ghSizeStr : '') + '\n수정: ' + ghDateStr;
                }
            }
        } catch(e) { /* silent fail */ }
        _dateFetchQueue.delete(f.path);
    }

    /* ── md-viewer로 파일 Push (PVShare 위임) ── */
    function pushFile(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._ghFile;
        if (!f) return;
        /* 파일 내용 읽어서 PVShare로 전달 */
        const cached = _fileContentCache[f.path];
        if (cached && cached.content) {
            PVShare.quickPush({ name: f.name, content: cached.content });
        } else {
            /* 캐시 없으면 API로 가져옴 */
            btn.textContent = '⟳';
            _apiFetch(`/contents/${encodeURIComponent(f.path)}?ref=${cfg.branch}`)
                .then(data => {
                    const content = decodeURIComponent(escape(atob(data.content.replace(/\n/g,''))));
                    _fileContentCache[f.path] = { content, sha: data.sha };
                    btn.textContent = '📤';
                    PVShare.quickPush({ name: f.name, content });
                })
                .catch(e => { btn.textContent = '📤'; alert('파일 읽기 실패: ' + e.message); });
        }
    }

    /* ── GitHub 폴더 삭제 ──────────────────────────────────
       전략: Git Trees API로 해당 폴더 내 모든 blob을 null SHA로 삭제 커밋
       빈 폴더(.gitkeep)는 .gitkeep 파일 삭제로 처리              */
    async function confirmDeleteFolder(btn) {
        const folderPath = btn.dataset.path;
        const ghIsEmpty  = btn.dataset.empty === 'true';
        if (!folderPath || !cfg) return;

        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const fullFolder = basePath + folderPath;

        /* 폴더 내 파일 목록 */
        const filesInFolder = allFiles.filter(f =>
            f.path === folderPath ||
            f.path.startsWith(folderPath + '/')
        );
        const fileCount = filesInFolder.length;

        /* 확인 모달 */
        const result = await _showGhFolderDeleteModal(folderPath, ghIsEmpty, fileCount);
        if (!result) return;

        const commitMsg = result.commitMsg || `Delete folder ${folderPath.split('/').pop()}`;

        try {
            App._toast('⟳ GitHub에서 폴더 삭제 중…');

            if (ghIsEmpty && fileCount === 0) {
                /* 빈 폴더: .gitkeep 파일만 삭제 */
                const keepPath = fullFolder + '/.gitkeep';
                try {
                    const data = await _apiFetch(`/contents/${encodeURIComponent(keepPath)}?ref=${cfg.branch}`);
                    await _apiFetch(`/contents/${encodeURIComponent(keepPath)}`, {
                        method : 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body   : JSON.stringify({
                            message: commitMsg,
                            sha    : data.sha,
                            branch : cfg.branch || 'main',
                        }),
                    });
                } catch(e2) { /* .gitkeep이 없어도 무시 */ }
                delete _ghEmptyFolders[folderPath];
                _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) }).catch(()=>{});
            } else {
                /* 비어있지 않은 폴더: Git Trees API로 일괄 삭제 */
                const refData    = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
                const headSHA    = refData.object.sha;
                const commitData = await _apiFetch(`/git/commits/${headSHA}`);
                const baseTree   = commitData.tree.sha;

                /* 삭제할 경로 목록 (SHA=null) */
                const treeItems = filesInFolder.map(f => ({
                    path: f.path,
                    mode: '100644',
                    type: 'blob',
                    sha : null,
                }));

                /* .gitkeep도 존재할 수 있으면 추가 */
                treeItems.push({
                    path: fullFolder + '/.gitkeep',
                    mode: '100644', type: 'blob', sha: null,
                });

                const newTree = await _apiFetch('/git/trees', {
                    method : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({ base_tree: baseTree, tree: treeItems }),
                });
                const newCommit = await _apiFetch('/git/commits', {
                    method : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({
                        message: commitMsg,
                        tree   : newTree.sha,
                        parents: [headSHA],
                    }),
                });
                await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
                    method : 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body   : JSON.stringify({ sha: newCommit.sha }),
                });

                /* 메모리에서 제거 */
                filesInFolder.forEach(f => {
                    delete _fileContentCache[f.path];
                });
                allFiles  = allFiles.filter(f =>
                    f.path !== folderPath && !f.path.startsWith(folderPath + '/')
                );
                filtered  = filtered.filter(f =>
                    f.path !== folderPath && !f.path.startsWith(folderPath + '/')
                );
                delete _ghEmptyFolders[folderPath];
                _ghPut('meta', 'emptyFolders', { folders: Object.keys(_ghEmptyFolders) }).catch(()=>{});
            }

            _render();
            App._toast(`🗑 "${folderPath}" 폴더 삭제 완료`);
            /* 백그라운드 재스캔 */
            refresh().catch(()=>{});
        } catch(e) {
            alert('폴더 삭제 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 폴더 삭제 확인 모달 ── */
    function _showGhFolderDeleteModal(folderPath, isEmpty, fileCount) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const folderName = folderPath.split('/').pop();
            const warnHtml = isEmpty
                ? `<div style="font-size:11px;color:#6af7b0;margin-top:6px">✅ 빈 폴더입니다. .gitkeep 파일이 삭제됩니다.</div>`
                : `<div style="font-size:11px;color:#f7a06a;margin-top:6px;line-height:1.7">
                    ⚠ 이 폴더 안의 <b style="color:#ff8080">${fileCount}개 파일</b>이 모두 GitHub에서 삭제됩니다.<br>
                    삭제 후 복구하려면 Git 히스토리를 사용해야 합니다.
                   </div>`;

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:2px solid rgba(247,106,106,.4);border-radius:12px;padding:20px 22px;min-width:320px;max-width:440px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;gap:9px;margin-bottom:14px">
                    <span style="font-size:20px">🗑</span>
                    <span style="font-size:14px;font-weight:700;color:#f76a6a">🐙 GitHub 폴더 삭제</span>
                </div>
                <div style="background:rgba(247,106,106,.08);border:1px solid rgba(247,106,106,.3);border-radius:8px;padding:12px 14px;margin-bottom:12px">
                    <div style="font-size:11px;color:var(--tx3);margin-bottom:4px">삭제할 폴더</div>
                    <div style="font-size:14px;font-weight:700;color:#f76a6a">${_esc(folderName)}</div>
                    <div style="font-size:10px;color:var(--tx3);font-family:var(--fm)">${_esc(folderPath)}</div>
                    ${warnHtml}
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">커밋 메시지</label>
                    <input id="gfdel-msg" type="text" value="Delete folder ${_esc(folderName)}"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="gfdel-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="gfdel-ok" style="padding:6px 18px;border-radius:6px;border:none;background:rgba(247,106,106,.2);border:1px solid rgba(247,106,106,.5);color:#f76a6a;font-size:12px;font-weight:700;cursor:pointer">🗑 삭제 확인</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('gfdel-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('gfdel-ok').onclick = () => {
                const msg = document.getElementById('gfdel-msg').value.trim();
                close({ commitMsg: msg || `Delete folder ${folderName}` });
            };
            const inp = document.getElementById('gfdel-msg');
            inp.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('gfdel-ok').click();
                if (e.key === 'Escape') close(null);
            });
            setTimeout(() => { inp.focus(); inp.select(); }, 50);
        });
    }

    /* ── GitHub 파일 이동 ─────────────────────────────────
       Git Trees API: 기존 경로 blob(null) + 새 경로 blob(sha) 단일 커밋  */
    async function moveFile(btn) {
        const row = btn.closest('.file-item');
        const f   = row && row._ghFile;
        if (!f) return;

        /* 이동 가능 폴더 목록 (현재 폴더 제외) */
        const currentFolder = f.path.includes('/')
            ? f.path.split('/').slice(0, -1).join('/')
            : '/';

        const folderSet = new Set(['/']);
        allFiles.forEach(ff => {
            const parts = ff.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });

        const folderOptions = [...folderSet].sort()
            .filter(p => p !== currentFolder)
            .map(p => ({ label: p === '/' ? '📁 (루트)' : '📂 ' + p, value: p }));

        const result = await _showGhMoveModal(f.name, folderOptions);
        if (!result) return;

        const { destFolder, commitMsg } = result;
        const basePath   = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const oldPath    = f.path;
        const newRelDir  = destFolder === '/' ? '' : destFolder + '/';
        const newPath    = basePath + newRelDir + f.name;

        if (newPath === oldPath) { App._toast('같은 폴더입니다'); return; }

        try {
            App._toast('⟳ GitHub에서 파일 이동 중…');

            /* 원본 파일 내용+SHA 취득 */
            let content, sha;
            const cached = _fileContentCache[oldPath];
            if (cached && cached.sha) {
                sha     = cached.sha;
                content = cached.content;
            } else {
                const data = await _apiFetch(`/contents/${encodeURIComponent(oldPath)}?ref=${cfg.branch}`);
                sha     = data.sha;
                content = decodeURIComponent(escape(atob(data.content.replace(/\n/g, ''))));
            }

            /* Git Trees API: 기존 경로 삭제(null) + 새 경로 추가 */
            const refData    = await _apiFetch(`/git/ref/heads/${cfg.branch}`);
            const headSHA    = refData.object.sha;
            const commitData = await _apiFetch(`/git/commits/${headSHA}`);
            const baseTree   = commitData.tree.sha;

            const blob = await _apiFetch('/git/blobs', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    content : btoa(unescape(encodeURIComponent(content))),
                    encoding: 'base64',
                }),
            });

            const newTree = await _apiFetch('/git/trees', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    base_tree: baseTree,
                    tree: [
                        { path: oldPath, mode: '100644', type: 'blob', sha: null },
                        { path: newPath, mode: '100644', type: 'blob', sha: blob.sha },
                    ],
                }),
            });
            const newCommit = await _apiFetch('/git/commits', {
                method : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({
                    message: commitMsg || `Move ${f.name} → ${destFolder === '/' ? '루트' : destFolder}`,
                    tree   : newTree.sha,
                    parents: [headSHA],
                }),
            });
            await _apiFetch(`/git/refs/heads/${cfg.branch}`, {
                method : 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body   : JSON.stringify({ sha: newCommit.sha }),
            });

            /* 캐시 갱신 */
            delete _fileContentCache[oldPath];
            _fileContentCache[newPath] = { content, sha: blob.sha };

            /* 탭 경로 업데이트 */
            const tab = TM.getAll().find(t => t.ghPath === oldPath);
            if (tab) {
                tab.ghPath = newPath;
                tab.ghSha  = blob.sha;
                TM.renderTabs();
            }

            App._toast(`✅ "${f.name}" → "${destFolder === '/' ? '루트' : destFolder}" 이동 완료`);
            await refresh();
        } catch(e) {
            alert('파일 이동 실패: ' + (e.message || e));
        }
    }

    /* ── GitHub 파일 이동 모달 ── */
    function _showGhMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9100;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';
            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:440px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 GitHub 파일 이동</span>
                    <button id="gmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_esc(fileName)}</b>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="gmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">커밋 메시지</label>
                    <input id="gmov-msg" type="text" value="Move ${_esc(fileName)}"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="gmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="gmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동 & Push</button>
                </div>`;
            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('gmov-close').onclick  = () => close(null);
            document.getElementById('gmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('gmov-ok').onclick = () => {
                close({
                    destFolder: document.getElementById('gmov-dest').value,
                    commitMsg : document.getElementById('gmov-msg').value.trim(),
                });
            };
        });
    }

    /* ── GitHub 폴더별 새 파일 만들기 (폴더 + 버튼에서 호출) ── */
    async function _createFileInFolder(folderPath) {
        if (!cfg) { alert('GitHub 연결 필요'); return; }

        const folderSet = new Set(['/']);
        allFiles.forEach(f => {
            const parts = f.path.split('/');
            for (let i = 1; i < parts.length; i++) {
                folderSet.add(parts.slice(0, i).join('/'));
            }
        });
        Object.keys(_ghEmptyFolders).forEach(fp => { if (fp) folderSet.add(fp); });
        const folderOptions = [...folderSet].sort().map(p =>
            `<option value="${p}" ${p === folderPath ? 'selected' : ''}>${p === '/' ? '📁 (루트)' : '📂 ' + p}</option>`
        ).join('');

        const result = await _ghNewItemModal({
            title: '📄 GitHub 새 파일',
            folderOptions,
            namePlaceholder: 'notes.md',
            nameLabel: '파일 이름 (.md 자동 추가)',
            okLabel: '✔ 에디터에서 열기 & Push',
        });
        if (!result) return;

        let fname = result.name.trim();
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[\\:*?"<>|]/g, '_');
        const basePath = cfg.path ? cfg.path.replace(/\/$/, '') + '/' : '';
        const folderPart = result.folder && result.folder !== '/' ? result.folder + '/' : '';
        const filePath = basePath + folderPart + safe;

        const title = safe.replace(/\.[^.]+$/, '');
        const initContent = '# ' + title + '\n\n';
        const tab = TM.newTab(title, initContent, 'md');
        tab.ghPath   = filePath;
        tab.ghBranch = cfg.branch || 'main';
        TM.markDirty();
        TM.renderTabs();

        try {
            App._toast('⟳ GitHub에 파일 생성 중…');
            const encoded = btoa(unescape(encodeURIComponent(initContent)));
            const res = await _apiFetch(`/contents/${filePath}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: 'Create ' + safe,
                    content: encoded,
                    branch: cfg.branch || 'main',
                }),
            });
            if (res && res.content && res.content.sha) {
                tab.ghSha = res.content.sha;
                _fileContentCache[filePath] = { content: initContent, sha: res.content.sha };
            }
            TM.markClean(tab.id);
            TM.renderTabs();
            App._toast('✅ ' + safe + ' 생성 & Push 완료');
            await refresh();
        } catch(e) {
            App._toast('⚠ 파일은 열렸으나 Push 실패: ' + (e.message || e));
        }
    }

    return {
        restore, refresh, search, showSettings, hideSettings, saveSettings, handleHdrSaveClick,
        reloadCfg: () => { cfg = _loadCfg(); },
        saveFile, createFile, pushLocalFiles, getRemoteSHAs,
        openRepoLink, cloneRepo, renameAndCommit,
        checkNewCommits, dismissCommitBanner, loadDeviceActivity,
        loadHistory, refreshHistory, filterHistory,
        quickConnect, isConnected, _render,
        createNewFile, createNewFolder, _createFileInFolder,
        getFolderOptionsForSave,
        confirmDelete, confirmDeleteFolder, moveFile, pushFile,
        toggleFoldAll, toggleAutoRefresh, showArIntervalSetting,
        syncHighlightFromActiveTab,
        get cfg() { return cfg; },
    };
})();


