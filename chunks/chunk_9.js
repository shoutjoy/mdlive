          </div>

          <!-- 로컬 / GitHub 탭 -->
          <div style="display:flex;border-bottom:1px solid var(--bd);background:var(--bg3);flex-shrink:0">
            <button id="pvs-tab-local" onclick="PVShare._switchTab('local')"
                style="flex:1;padding:9px;font-size:12px;font-weight:600;border:none;cursor:pointer;
                    border-bottom:2px solid #58c8f8;
                    background:rgba(88,200,248,.08);color:#58c8f8;
                    transition:all .15s">
                💻 로컬</button>
            <button id="pvs-tab-github" onclick="PVShare._switchTab('github')"
                style="flex:1;padding:9px;font-size:12px;font-weight:600;border:none;cursor:pointer;
                    border-bottom:2px solid transparent;
                    background:transparent;color:var(--tx3);
                    transition:all .15s">
                🐙 GitHub</button>
          </div>

          <!-- 검색 -->
          <div style="padding:8px 14px;border-bottom:1px solid var(--bd);flex-shrink:0">
            <input id="pvs-search" type="text" placeholder="파일 검색…"
                oninput="PVShare._search(this.value)"
                style="width:100%;background:var(--bg3);border:1px solid var(--bd);
                    border-radius:6px;color:var(--tx);font-size:12px;
                    padding:6px 10px;outline:none;box-sizing:border-box">
          </div>

          <!-- 파일 목록 -->
          <div id="pvs-list" style="flex:1;overflow-y:auto;padding:6px 0;min-height:120px">
            <div style="text-align:center;padding:30px;color:var(--tx3);font-size:12px">
              ⟳ 파일 목록 불러오는 중…
            </div>
          </div>

          <!-- 하단 액션: [새파일] [새폴더] [자동새로고침] [25s] {설정} -->
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;
              border-top:1px solid var(--bd);background:var(--bg3);flex-shrink:0;flex-wrap:wrap">
            <button id="pvs-btn-newfile" onclick="PVShare._dispatchNewFile()" title="새 파일 만들기"
                style="flex:1;min-width:90px;padding:7px;border-radius:6px;
                    background:rgba(255,255,255,.06);border:1px solid var(--bd);
                    color:var(--tx2);font-size:12px;cursor:pointer">
                새 파일</button>
            <button id="pvs-btn-newfolder" onclick="PVShare._dispatchNewFolder()" title="새 폴더 만들기"
                style="flex:1;min-width:90px;padding:7px;border-radius:6px;
                    background:rgba(255,255,255,.06);border:1px solid var(--bd);
                    color:var(--tx2);font-size:12px;cursor:pointer">
                새 폴더</button>
            <button id="pvs-ar-btn" onclick="PVShare._toggleAutoRefresh()"
                title="GitHub 폴더 목록 자동 새로고침 ON/OFF"
                style="border-radius:5px;font-size:11px;padding:4px 10px;cursor:pointer;
                    font-weight:600;transition:all .2s;
                    color:#6af7b0;border:1px solid rgba(106,247,176,.35);
                    background:rgba(106,247,176,.1)">🔄 자동새로고침 ON</button>
            <span id="pvs-ar-countdown"
                style="font-size:11px;color:var(--tx3);min-width:28px;text-align:center;display:none"></span>
            <button onclick="PVShare._showArIntervalSetting()" title="자동 새로고침 간격(초) 설정"
                style="padding:6px 12px;border-radius:5px;border:1px solid var(--bd);
                    background:rgba(255,255,255,.06);color:var(--tx2);font-size:11px;cursor:pointer">
                ⚙ 설정</button>
          </div>
        </div>`;

        document.body.appendChild(ov);

        /* 닫기 */
        document.getElementById('pvs-close').onclick = () => {
            _stopAutoRefresh();
            ov.remove();
        };
        /* 모달 열릴 때 자동새로고침 버튼 상태 반영 + 시작 */
        setTimeout(() => {
            _arUpdateBtn();
            if (_arEnabled) _startAutoRefresh();
        }, 50);
        ov.onclick = (e) => { if (e.target === ov) ov.remove(); };

        /* 기본 탭: 로컬 탭 활성 */
        setTimeout(() => { _switchTab('local'); }, 0);
    }

    /* ── 파일 목록 렌더 ── */
    let _allFiles = [];
    let _searchQ  = '';
    let _currentGitHubPath = '';  /* GitHub 탭에서 현재 보고 있는 경로 (자동새로고침용) */

    async function _loadList(path = '') {
        const listEl = document.getElementById('pvs-list');
        if (!listEl) return;
        _currentGitHubPath = path;  /* 자동새로고침 시 같은 경로로 재요청 */
        _setStatus('불러오는 중…');

        const vcfg = _loadCfg();
        if (!vcfg?.repo) {
            listEl.innerHTML = `
            <div style="text-align:center;padding:30px;color:#f7c060;font-size:12px">
                ⚠ 저장소가 설정되지 않았습니다.<br>
                <button onclick="PVShare._showSettings()"
                    style="margin-top:10px;padding:6px 14px;border-radius:6px;
                        background:rgba(247,192,96,.15);border:1px solid rgba(247,192,96,.3);
                        color:#f7c060;font-size:12px;cursor:pointer">⚙ 설정하기</button>
            </div>`;
            _setStatus('');
            return;
        }

        try {
            const items = await _listPath(path);
            _allFiles = Array.isArray(items) ? items : [];
            _renderList(_allFiles);
            _setStatus('');
        } catch(e) {
            listEl.innerHTML = `
            <div style="text-align:center;padding:20px;color:#f76a6a;font-size:12px">
                ❌ ${e.message}<br>
                <button onclick="PVShare._loadList()"
                    style="margin-top:8px;padding:5px 12px;border-radius:5px;
                        background:rgba(247,106,106,.1);border:1px solid rgba(247,106,106,.3);
                        color:#f76a6a;font-size:11px;cursor:pointer">다시 시도</button>
            </div>`;
            _setStatus('오류');
        }
    }

    function _renderList(items) {
        const listEl = document.getElementById('pvs-list');
        if (!listEl) return;

        const q = _searchQ.toLowerCase();
        const filtered = q ? items.filter(f => f.name.toLowerCase().includes(q)) : items;

        if (!filtered.length) {
            listEl.innerHTML = `<div style="text-align:center;padding:24px;
                color:var(--tx3);font-size:12px">파일이 없습니다</div>`;
            return;
        }

        /* 폴더 먼저, 파일 나중 */
        const sorted = [...filtered].sort((a, b) => {
            if (a.type === b.type) return a.name.localeCompare(b.name);
            return a.type === 'dir' ? -1 : 1;
        });

        listEl.innerHTML = sorted.map(f => {
            const isDir  = f.type === 'dir';
            const icon   = isDir ? '📁' : (f.name.endsWith('.md') ? '📄' : '📎');
            const link   = isDir ? '' : _makeLink(f.path);
            const linkBtn = isDir ? '' : `
                <button onclick="event.stopPropagation();PVShare._copyLink('${_escQ(link)}',this)"
                    title="뷰어 링크 복사"
                    style="background:rgba(88,200,248,.12);border:1px solid rgba(88,200,248,.3);
                        border-radius:4px;color:#58c8f8;font-size:10px;
                        padding:2px 7px;cursor:pointer;flex-shrink:0">🔗</button>`;

            return `<div class="pvs-item" data-path="${_escQ(f.path)}" data-type="${f.type}"
                data-sha="${f.sha || ''}"
                style="display:flex;align-items:center;gap:6px;
                    padding:5px 14px;cursor:pointer;border-radius:4px;
                    transition:background .1s"
                onmouseover="this.style.background='rgba(255,255,255,.05)'"
                onmouseout="this.style.background=''"
                onclick="PVShare._itemClick(this)">
              <span style="flex-shrink:0;font-size:13px">${icon}</span>
              <span style="flex:1;font-size:12px;color:var(--tx);
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(f.name)}</span>
              ${linkBtn}
              <button onclick="event.stopPropagation();PVShare._moveFile(this)"
                  data-path="${_escQ(f.path)}" data-type="${f.type}"
                  title="이동"
                  style="background:rgba(255,255,255,.06);border:1px solid var(--bd);
                      border-radius:4px;color:var(--tx3);font-size:10px;
                      padding:2px 7px;cursor:pointer;flex-shrink:0">↗</button>
              <button onclick="event.stopPropagation();PVShare._deleteItem(this)"
                  data-path="${_escQ(f.path)}" data-type="${f.type}"
                  data-sha="${_escQ(f.sha || '')}" data-name="${_escQ(f.name)}"
                  title="삭제"
                  style="background:rgba(247,106,106,.1);border:1px solid rgba(247,106,106,.25);
                      border-radius:4px;color:#f76a6a;font-size:10px;
                      padding:2px 7px;cursor:pointer;flex-shrink:0">🗑</button>
            </div>`;
        }).join('');
    }

    function _escQ(s) { return String(s).replace(/'/g,"\\'").replace(/"/g,'&quot;'); }
    function _esc(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    /* ── 아이템 클릭: 폴더면 하위 목록, 파일이면 열기 ── */
    function _itemClick(row) {
        const path = row.dataset.path;
        const type = row.dataset.type;
        if (type === 'dir') {
            _loadList(path);
        }
    }

    /* ── 검색 ── */
    function _search(q) {
        _searchQ = q;
        _renderList(_allFiles);
    }

    /* ── 링크 복사 ── */
    function _copyLink(url, btn) {
        navigator.clipboard.writeText(url).then(() => {
            const orig = btn.textContent;
            btn.textContent = '✅';
            btn.style.color = '#6af7b0';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
            App._toast('🔗 링크 복사됨: ' + url);
        }).catch(() => {
            prompt('링크를 복사하세요:', url);
        });
    }

    /* ── 상태 텍스트 ── */
    function _setStatus(msg) {
        const el = document.getElementById('pvs-status');
        if (el) el.textContent = msg;
    }

    /* ── 새로고침 ── */
    function _refresh() { _loadList(); }

    /* ── Pull: 원격 최신 파일 목록 갱신 ── */
    function _pull() {
        _setStatus('Pull 중…');
        _loadList().then(() => App._toast('⬇ Pull 완료'));
    }

    /* ── Push: 현재 에디터 문서를 docs/ 에 push ── */
    async function _pushCurrent() {
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        if (!tab) { App._toast('⚠ 열린 문서가 없습니다'); return; }

        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const defaultName = (tab.title || '문서')
            .replace(/[^a-zA-Z0-9가-힣._-]/g,'_')
            .replace(/\.md$/i,'') + '.md';

        const name = prompt('저장할 파일명 (docs/ 안에 저장됩니다):', defaultName);
        if (!name) return;

        const filePath = 'docs/' + name;
        const content  = document.getElementById('editor')?.value || '';
        _setStatus('Push 중…');

        try {
            let sha = null;
            try { const ex = await _getFile(filePath); sha = ex.sha; } catch(e) {}
            await _putFile(filePath, content, `Publish: ${name}`, sha);
            _setStatus('');
            _loadList();
            const link = _makeLink(filePath);
            App._toast('✅ Push 완료');
            _showLinkResult(link, name);
        } catch(e) {
            _setStatus('오류');
            alert('Push 실패: ' + e.message);
        }
    }

    /* ── 로컬 / GitHub 탭 전환 ── */
    let _activeTab = 'local';   /* 현재 활성 탭: 'local' | 'github' */

    /* ── 자동 새로고침 ─────────────────────────────────────── */
    const AR_KEY      = 'pvs_auto_refresh';   // localStorage 키
    const AR_INTERVAL_KEY = 'pvs_ar_interval'; // 간격(초) 저장 키
    function _getArInterval() { return Math.max(10, parseInt(localStorage.getItem(AR_INTERVAL_KEY) || '30', 10) || 30); }
    let _arEnabled    = localStorage.getItem(AR_KEY) !== 'off'; // 기본 ON
    let _arTimer      = null;   // setInterval ID
    let _arCountdown  = 0;      // 남은 초
    let _arTick       = null;   // 카운트다운 ticker

    function _arSaveState() {
        localStorage.setItem(AR_KEY, _arEnabled ? 'on' : 'off');
    }

    function _arUpdateBtn() {
        const btn = document.getElementById('pvs-ar-btn');
        if (!btn) return;
        if (_arEnabled) {
            btn.textContent = '🔄 자동새로고침 ON';
            btn.style.color      = '#6af7b0';
            btn.style.borderColor = 'rgba(106,247,176,.35)';
            btn.style.background  = 'rgba(106,247,176,.1)';
        } else {
            btn.textContent = '🔄 자동새로고침 OFF';
            btn.style.color      = 'var(--tx3)';
            btn.style.borderColor = 'var(--bd)';
            btn.style.background  = 'rgba(255,255,255,.04)';
        }
    }

    function _arUpdateCountdown() {
        const el = document.getElementById('pvs-ar-countdown');
        if (!el) return;
        if (_arEnabled && _arCountdown > 0) {
            el.textContent = _arCountdown + 's';
            el.style.display = 'inline';
        } else {
            el.style.display = 'none';
        }
    }

    function _startAutoRefresh() {
        _stopAutoRefresh();
        if (!_arEnabled) return;
        const intervalSec = _getArInterval();
        _arCountdown = intervalSec;
        _arUpdateCountdown();

        // 카운트다운 ticker (1초마다)
        _arTick = setInterval(() => {
            _arCountdown--;
            _arUpdateCountdown();
            if (_arCountdown <= 0) {
                // GitHub 탭 활성 상태일 때만 GitHub 폴더 목록 새로고침 (현재 경로 유지)
                if (_activeTab === 'github') {
                    _loadList(_currentGitHubPath).catch(() => {});
                }
                _arCountdown = _getArInterval();
            }
        }, 1000);
    }

    function _stopAutoRefresh() {
        if (_arTimer)  { clearInterval(_arTimer);  _arTimer   = null; }
        if (_arTick)   { clearInterval(_arTick);   _arTick    = null; }
        _arCountdown = 0;
        _arUpdateCountdown();
    }

    function _toggleAutoRefresh() {
        _arEnabled = !_arEnabled;
        _arSaveState();
        _arUpdateBtn();
        if (_arEnabled) {
            _startAutoRefresh();
            App._toast('🔄 자동새로고침 ON (' + _getArInterval() + '초마다 GitHub 폴더)');
        } else {
            _stopAutoRefresh();
            App._toast('🔄 자동새로고침 OFF');
        }
    }

    /* 자동새로고침 간격(초) 설정 */
    function _showArIntervalSetting() {
        const cur = _getArInterval();
        const v = prompt('자동 새로고침 간격 (초)\nGitHub 탭에서 이 간격마다 폴더 목록을 갱신합니다.', String(cur));
        if (v == null) return;
        const num = parseInt(v, 10);
        if (!(num >= 10 && num <= 600)) {
            App._toast('⚠ 10~600 초 사이로 입력하세요');
            return;
        }
        localStorage.setItem(AR_INTERVAL_KEY, String(num));
        if (_arEnabled) _startAutoRefresh();
        App._toast('✅ 간격 ' + num + '초로 저장');
    }

    function _switchTab(tab) {
        _activeTab = tab;
        const localBtn  = document.getElementById('pvs-tab-local');
        const githubBtn = document.getElementById('pvs-tab-github');
        if (!localBtn || !githubBtn) return;

        if (tab === 'local') {
            localBtn.style.borderBottomColor  = '#58c8f8';
            localBtn.style.background         = 'rgba(88,200,248,.08)';
            localBtn.style.color              = '#58c8f8';
            githubBtn.style.borderBottomColor = 'transparent';
            githubBtn.style.background        = 'transparent';
            githubBtn.style.color             = 'var(--tx3)';
            _renderLocalFiles();
        } else {
            githubBtn.style.borderBottomColor = '#a090ff';
            githubBtn.style.background        = 'rgba(160,144,255,.08)';
            githubBtn.style.color             = '#a090ff';
            localBtn.style.borderBottomColor  = 'transparent';
            localBtn.style.background         = 'transparent';
            localBtn.style.color              = 'var(--tx3)';
            _loadList();
        }
        /* 하단 버튼 라벨을 탭에 맞게 갱신 */
        _updateBottomBtns(tab);
    }

    /* 하단 새파일/새폴더 버튼 라벨 갱신 */
    function _updateBottomBtns(tab) {
        const btnFile   = document.getElementById('pvs-btn-newfile');
        const btnFolder = document.getElementById('pvs-btn-newfolder');
        if (!btnFile || !btnFolder) return;
        if (tab === 'local') {
            btnFile.textContent   = '새 파일';
            btnFolder.textContent = '새 폴더';
            btnFile.title   = '로컬 공개노트 폴더에 새 파일 생성';
            btnFolder.title = '로컬 공개노트 폴더에 새 폴더 생성';
        } else {
            btnFile.textContent   = '새 파일';
            btnFolder.textContent = '새 폴더';
            btnFile.title   = 'md-viewer GitHub 저장소에 새 파일 생성';
            btnFolder.title = 'md-viewer GitHub 저장소에 새 폴더 생성';
        }
    }

    /* ── 로컬 탭 파일 목록 렌더 ── */
    /* ══════════════════════════════════════════════════
       공개노트 로컬 탭 — PVShare 전용 폴더 렌더
    ══════════════════════════════════════════════════ */
    function _renderLocalFiles() {
        const list = document.getElementById('pvs-list');
        if (!list) return;

        const curFolder = _pvFolderName || _pvLoadFolderName() || '';
        const files     = _pvFiles || [];

        /* ── 폴더 상태 헤더 (sticky) ── */
        const folderBar = `
            <div id="pvs-local-folderbar" style="display:flex;align-items:center;gap:8px;
                padding:8px 14px;background:var(--bg3);border-bottom:1px solid var(--bd);
                position:sticky;top:0;z-index:2;flex-shrink:0">
              <span style="font-size:12px">📂</span>
              <span id="pvs-local-foldername" style="flex:1;font-size:11px;font-weight:600;
                  color:${curFolder ? 'var(--tx)' : 'var(--tx3)'};
                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  ${curFolder || '공개노트 폴더 미선택'}</span>
              <button onclick="PVShare._selectLocalFolder()"
                  style="padding:3px 11px;border-radius:5px;white-space:nowrap;flex-shrink:0;
                      border:1px solid rgba(88,200,248,.45);font-size:10.5px;cursor:pointer;
                      background:rgba(88,200,248,.1);color:#58c8f8">
                  ${curFolder ? '📂 변경' : '📂 폴더 선택'}</button>
              ${curFolder ? `<button onclick="PVShare._pvRefresh()"
                  title="폴더 새로고침"
                  style="padding:3px 8px;border-radius:5px;border:1px solid var(--bd);
                      background:rgba(255,255,255,.06);color:var(--tx3);font-size:11px;cursor:pointer">↻</button>` : ''}
              ${curFolder ? `<button onclick="PVShare._pvOpenLocalDir()"
                  title="연결된 로컬 폴더 탐색기에서 열기"
                  style="padding:3px 9px;border-radius:5px;border:1px solid rgba(247,201,106,.4);
                      background:rgba(247,201,106,.1);color:#f7c96a;font-size:10.5px;cursor:pointer;white-space:nowrap">📂 열기</button>` : ''}
            </div>`;

        /* 폴더 없거나 파일 없음 */
        if (!files.length) {
            list.innerHTML = folderBar + `
                <div style="text-align:center;padding:30px 16px;color:var(--tx3);font-size:12px;line-height:1.8">
                  ${curFolder
                    ? '<span style="font-size:22px">📭</span><br>파일이 없거나 스캔 중입니다.<br><button onclick="PVShare._pvRefresh()" style="margin-top:8px;padding:4px 14px;border-radius:5px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:11px;cursor:pointer">↻ 다시 스캔</button>'
                    : '<span style="font-size:22px">💻</span><br>공개노트(md-viewer)와 공유할<br>로컬 폴더를 선택하세요.'
                  }
                </div>`;
            return;
        }

        /* 폴더 → 파일 구분 정렬: .md 먼저, 나머지 나중 / isDir 빈폴더 별도 */
        const emptyDirs = files.filter(f => f.isDir);
        const realFiles = files.filter(f => !f.isDir);
        const mdFiles   = realFiles.filter(f => f.name.match(/\.md$/i));
        const others    = realFiles.filter(f => !f.name.match(/\.md$/i));
        const sorted    = [...mdFiles, ...others];

        /* 폴더 그룹핑 (folder 값 기준) */
        const grouped = {};
        sorted.forEach(f => {
            const grp = f.folder || '';
            if (!grouped[grp]) grouped[grp] = [];
            grouped[grp].push(f);
        });

        /* 빈 폴더: 아직 grouped 에 없는 경우 빈 배열로 등록 */
        emptyDirs.forEach(d => {
            /* d.folder = 부모 경로, d.path = 이 폴더 경로 */
            /* 빈 폴더를 부모 그룹 아래 배치 */
            const grp = d.folder || '';
            if (!grouped[grp]) grouped[grp] = [];
            grouped[grp].push(d);   /* isDir:true 항목 포함 */
        });

        let html = folderBar;

        Object.keys(grouped).sort().forEach(grpKey => {
            /* 서브폴더 헤더 */
            if (grpKey) {
                html += `<div style="display:flex;align-items:center;
                    padding:5px 14px 3px;font-size:10.5px;color:var(--tx3);
                    font-weight:600;background:rgba(255,255,255,.02);
                    border-bottom:1px solid rgba(255,255,255,.04)">
                  <span style="flex:1">📁 ${_escL(grpKey)}</span>
                  <button
                      onclick="event.stopPropagation();PVShare._pvCreateFileInFolder('${_escQL(grpKey)}')"
                      title="이 폴더에 새 파일 만들기"
                      style="padding:1px 7px;border-radius:4px;font-size:11px;cursor:pointer;flex-shrink:0;
                          border:1px solid rgba(106,247,176,.3);background:rgba(106,247,176,.07);color:#6af7b0;
                          line-height:1.4">📄＋</button>
                  <button
                      onclick="event.stopPropagation();PVShare._pvCreateFolderIn('${_escQL(grpKey)}')"
                      title="이 폴더 안에 새 하위 폴더 만들기"
                      style="padding:1px 7px;border-radius:4px;font-size:11px;cursor:pointer;flex-shrink:0;
                          border:1px solid rgba(247,201,106,.3);background:rgba(247,201,106,.07);color:#f7c96a;
                          line-height:1.4">📁＋</button>
                </div>`;
            }
            grouped[grpKey].forEach(f => {
                /* ── 빈 폴더 항목 (isDir:true) ── */
                if (f.isDir) {
                    html += `<div class="pvs-local-item pvs-empty-dir"
                        data-path="${_escQL(f.path)}"
                        data-name="${_escQL(f.name)}"
                        data-folder="${_escQL(f.folder || '')}"
                        style="display:flex;align-items:center;gap:6px;
                            padding:5px 14px 5px 24px;
                            border-bottom:1px solid rgba(255,255,255,.025);
                            font-size:11.5px;color:var(--tx3)">
                      <span style="font-size:12px;flex-shrink:0">📁</span>
                      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-style:italic">${_escL(f.name)}</span>
                      <span style="font-size:10px;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:4px;flex-shrink:0">빈 폴더</span>
                    </div>`;
                    return;
                }
                const icon = f.name.match(/\.md$/i) ? '📝' : '📄';
                /* data-path / data-name 에 경로 저장 → 함수에서 closest로 읽음
                   JSON.stringify를 onclick 속성에 직접 삽입하면
                   큰따옴표 충돌로 HTML이 깨지므로 btn-only 방식 사용 */
                html += `
                <div class="pvs-local-item"
                    data-path="${_escQL(f.path)}"
                    data-name="${_escQL(f.name)}"
                    data-folder="${_escQL(f.folder || '')}"
                    style="display:flex;align-items:center;gap:6px;
                        padding:6px 14px;border-bottom:1px solid rgba(255,255,255,.035);
                        font-size:12px;color:var(--tx2);cursor:pointer;transition:background .1s"
                    onmouseover="this.style.background='rgba(255,255,255,.045)'"
                    onmouseout="this.style.background=''"
                    onclick="PVShare._pvOpenFile(this)"
                    ontouchstart="(function(row,ev){
                        if(ev.target.closest('button')){return;}
                        var already=row.classList.contains('touch-sel');
                        document.querySelectorAll('.pvs-local-item.touch-sel').forEach(function(el){if(el!==row)el.classList.remove('touch-sel');});
                        if(already){PVShare._pvOpenFile(row);row.classList.remove('touch-sel');}
                        else{row.classList.add('touch-sel');ev.preventDefault();}
                    })(this,event)">
                  <span style="font-size:12px;flex-shrink:0">${icon}</span>
                  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${_escL(f.name)}</span>
                  <!-- 비공개 커밋 (mdliveData GH) -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvPushPrivate(this)"
                      title="비공개 저장소(mdliveData)에 커밋"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(160,144,255,.35);background:rgba(160,144,255,.1);color:#a090ff">🐙</button>
                  <!-- 공개 커밋 (md-viewer GitHub) -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvPushPublic(this)"
                      title="공개 저장소(md-viewer)에 커밋"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(106,247,176,.35);background:rgba(106,247,176,.1);color:#6af7b0">📤</button>
                  <!-- 이동 -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvMoveFile(this)"
                      title="파일 이동 (로컬 폴더)"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.05);color:var(--tx3)">↗</button>
                  <!-- 삭제 -->
                  <button class="pvs-act-btn" onclick="event.stopPropagation();PVShare._pvDeleteFile(this)"
                      title="파일 삭제 (로컬)"
                      style="padding:2px 7px;border-radius:4px;flex-shrink:0;font-size:10px;cursor:pointer;
                          border:1px solid rgba(247,106,106,.3);background:rgba(247,106,106,.08);color:#f76a6a">🗑</button>
                </div>`;
            });
        });

        list.innerHTML = html;
    }

    /* ── 공개노트 로컬 폴더를 탐색기에서 열기 ── */
    function _pvOpenLocalDir() {
        if (!_pvDirHandle) { App._toast('⚠ 폴더를 먼저 선택하세요'); return; }
        /* 브라우저 보안 정책 상 직접 탐색기 실행 불가.
           폴더 이름과 경로를 알려주고 선택을 유도 */
        const name = _pvFolderName || _pvDirHandle.name || '?';
        App._toast('📂 폴더: ' + name + ' — 탐색기에서 해당 폴더를 찾아 여세요');
    }

    /* ── 로컬 폴더 새로고침 ── */
    async function _pvRefresh() {
        if (!_pvDirHandle) {
            App._toast('⚠ 폴더가 선택되지 않았습니다');
            return;
        }
        const ok = await _pvRequestPermission();
        if (!ok) { App._toast('⚠ 폴더 접근 권한이 필요합니다'); return; }
        App._toast('⟳ 스캔 중…');
        await _pvSync();
        _renderLocalFiles();
    }

    /* ── 로컬 파일 에디터로 열기 ── */
    /* btnOrRow: .pvs-local-item 행 자체 또는 그 안의 요소 */
    function _pvOpenFile(btnOrRow) {
        const row  = btnOrRow?.closest ? (btnOrRow.closest('.pvs-local-item') || btnOrRow) : btnOrRow;
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다: ' + path); return; }
        if (f.content === null || f.content === undefined) {
            App._toast('⚠ 내용을 읽을 수 없는 파일입니다');
            return;
        }
        if (typeof TM !== 'undefined') {
            TM.newTab({ title: name, content: f.content, path: f.path });
        } else if (typeof App !== 'undefined') {
            const ed = document.getElementById('editor');
            if (ed) { ed.value = f.content; App.render(); }
        }
        App._toast('📝 열기: ' + name);
    }

    /* ── 폴더 경로 → FileSystemDirectoryHandle 탐색 헬퍼 ── */
    /* create=true 이면 경로 상의 폴더가 없어도 생성하면서 진행 */
    async function _pvGetDirHandle(folderPath, create = false) {
        let h = _pvDirHandle;
        if (!folderPath) return h;
        const parts = folderPath.split('/');
        for (const part of parts) {
            if (!part) continue;
            h = await h.getDirectoryHandle(part, { create });
        }
        return h;
    }

    /* ── 파일 내용 헬퍼 ── */
    async function _pvGetContent(path) {
        /* 1) 이미 스캔된 파일에서 가져오기 (빈 문자열도 유효) */
        const cached = _pvFiles.find(x => x.path === path);
        if (cached && cached.content !== null && cached.content !== undefined) {
            return cached.content;
        }
        /* 2) dirHandle 통해 직접 읽기 */
        if (!_pvDirHandle) throw new Error('폴더 핸들 없음 — 폴더를 다시 선택하세요');
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('읽기 권한이 거부되었습니다');
        } catch(e) { /* 이미 granted인 경우 에러 무시 */ }
        const parts = path.split('/');
        let h = _pvDirHandle;
        for (let i = 0; i < parts.length - 1; i++) {
            h = await h.getDirectoryHandle(parts[i]);
        }
        const fileH = await h.getFileHandle(parts[parts.length - 1]);
        const file  = await fileH.getFile();
        return file.text();
    }

    /* ── 비공개 커밋 (mdliveData GH 저장소) ── */
    async function _pvPushPrivate(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!GH.isConnected()) { App._toast('⚠ GH(mdliveData) 연결 설정이 필요합니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const origTxt = btn.textContent;
        btn.textContent = '⟳'; btn.disabled = true;
        try {
            /* 권한 확인 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('폴더 읽기 권한이 필요합니다');

            const content = await _pvGetContent(path);
            if (content === null || content === undefined) throw new Error('파일 내용을 읽을 수 없습니다');

            const ghCfg  = GH.cfg;
            const base   = ghCfg.basePath ? ghCfg.basePath.replace(/\/$/, '') + '/' : '';
            const ghPath = base + name;

            let sha = null;
            try {
                const info = await fetch(
                    `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(ghPath)}?ref=${ghCfg.branch}`,
                    { headers: { 'Authorization': `token ${ghCfg.token}`, 'Accept': 'application/vnd.github.v3+json' } }
                ).then(r => r.ok ? r.json() : null);
                if (info?.sha) sha = info.sha;
            } catch(e) {}

            const b64  = btoa(unescape(encodeURIComponent(content)));
            const body = { message: `Upload: ${name}`, content: b64, branch: ghCfg.branch };
            if (sha) body.sha = sha;

            const res = await fetch(
                `https://api.github.com/repos/${ghCfg.repo}/contents/${encodeURIComponent(ghPath)}`,
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
            btn.textContent = origTxt; btn.disabled = false;
            App._toast(`🐙 비공개 커밋 완료: ${name}`);
        } catch(e) {
            btn.textContent = origTxt; btn.disabled = false;
            App._toast('❌ 비공개 커밋 실패: ' + e.message);
        }
    }

    /* ── 공개 커밋 (md-viewer GitHub 저장소) ── */
    async function _pvPushPublic(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn?.closest?.('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); App._toast('⚠ md-viewer 저장소 미설정'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const origTxt = (btn && btn.textContent) || '📤';
        if (btn) { btn.textContent = '⟳'; btn.disabled = true; }
        try {
            /* 권한 확인 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'read' });
            if (perm !== 'granted') throw new Error('폴더 읽기 권한이 필요합니다');

            const content  = await _pvGetContent(path);
            if (content === null || content === undefined) throw new Error('파일 내용을 읽을 수 없습니다');

            const filePath = 'docs/' + name;
            let sha = null;
            try { const ex = await _getFile(filePath); if (ex?.sha) sha = ex.sha; } catch(e) {}

            await _putFile(filePath, content, `Publish: ${name}`, sha);
            if (btn) { btn.textContent = origTxt; btn.disabled = false; }

            const link = _makeLink(filePath);
            navigator.clipboard.writeText(link).catch(() => {});
            App._toast(`📤 공개 커밋 완료: ${name}  🔗링크 복사됨`);
        } catch(e) {
            if (btn) { btn.textContent = origTxt; btn.disabled = false; }
            App._toast('❌ 공개 커밋 실패: ' + e.message);
        }
    }

    /* ── 이동 모달 UI (PVShare 전용) ── */
    function _pvShowMoveModal(fileName, folderOptions) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-move-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-move-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9600;background:rgba(0,0,0,.68);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.6)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">📦 파일 이동</span>
                    <button id="pvmov-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="font-size:12px;color:var(--tx2);margin-bottom:12px;padding:8px 10px;background:var(--bg3);border-radius:6px">
                    📝 <b>${_escL(fileName)}</b>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">이동할 폴더 선택</label>
                    <select id="pvmov-dest" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvmov-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvmov-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 이동</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvmov-close').onclick  = () => close(null);
            document.getElementById('pvmov-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvmov-ok').onclick = () => {
                close(document.getElementById('pvmov-dest').value);
            };
        });
    }

    /* ── 로컬 파일 이동 (파일시스템 직접 이동) ── */
    async function _pvMoveFile(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다'); return; }

        /* 이동 가능한 폴더 목록 수집 — 모든 상위 경로 + isDir 빈폴더 포함 */
        const currentFolder = f.folder || '';
        const folderSet = new Set(['']);  /* 루트 항상 포함 */
        _pvFiles.forEach(x => {
            const parts = (x.folder || '').split('/');
            let acc = '';
            for (const p of parts) {
                if (!p) continue;
                acc = acc ? acc + '/' + p : p;
                folderSet.add(acc);
            }
            if (x.isDir) folderSet.add(x.path);
        });

        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet]
            .filter(p => p !== '' && p !== currentFolder)
            .sort()
            .forEach(folderPath => {
                const depth = (folderPath.match(/\//g) || []).length;
                const label = '📂 ' + '  '.repeat(depth) + folderPath.split('/').pop() + '  (' + folderPath + ')';
                folderOptions.push({ label, value: folderPath });
            });

        const destFolder = await _pvShowMoveModal(name, folderOptions);
        if (destFolder === null) return; /* 취소 */

        const destPath = destFolder ? destFolder + '/' + name : name;
        if (destPath === path) { App._toast('ℹ 같은 폴더입니다'); return; }

        const origTxt = btn.textContent;
        btn.textContent = '⟳'; btn.disabled = true;
        try {
            /* 쓰기 권한 요청 */
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

            /* 원본 파일 내용 읽기 */
            const content = await _pvGetContent(path);

            /* 대상 폴더 핸들 */
            const destDirH = await _pvGetDirHandle(destFolder);

            /* 대상 위치에 파일 쓰기 */
            const newFH = await destDirH.getFileHandle(name, { create: true });
            const wr    = await newFH.createWritable();
            await wr.write(content);
            await wr.close();

            /* 원본 삭제 */
            const srcDirH = await _pvGetDirHandle(f.folder || '');
            await srcDirH.removeEntry(name);

            /* 목록 재스캔 & UI 갱신 */
            await _pvSync();
            _renderLocalFiles();
            App._toast(`✅ "${name}" → "${destFolder || '루트'}" 이동 완료`);
        } catch(e) {
            btn.textContent = origTxt; btn.disabled = false;
            App._toast('❌ 이동 실패: ' + e.message);
        }
    }

    /* ── 로컬 파일 삭제 (파일시스템 + 목록 갱신) ── */
    async function _pvDeleteFile(btn) {
        /* btn: 클릭된 버튼 요소. 파일 정보는 .pvs-local-item data 속성에서 읽음 */
        const row  = btn.closest('.pvs-local-item');
        const path = row?.dataset?.path || '';
        const name = row?.dataset?.name || path.split('/').pop();
        if (!path) { App._toast('⚠ 파일 경로를 찾을 수 없습니다'); return; }
        if (!_pvDirHandle) { App._toast('⚠ 공개노트 폴더가 선택되지 않았습니다'); return; }

        const f = _pvFiles.find(x => x.path === path);
        if (!f) { App._toast('⚠ 파일을 찾을 수 없습니다'); return; }

        /* DelConfirm 모달 사용 */
        DelConfirm.show({
            name,
            path,
            type: 'local',
            onConfirm: async () => {
                try {
                    const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
                    if (perm !== 'granted') throw new Error('쓰기 권한이 거부되었습니다');

                    /* 부모 폴더 핸들 탐색 */
                    const parentH = await _pvGetDirHandle(f.folder || '');
                    await parentH.removeEntry(name);

                    /* 메모리 목록 즉시 갱신 */
                    _pvFiles = _pvFiles.filter(x => x.path !== path);
                    _renderLocalFiles();
                    App._toast(`🗑 "${name}" 삭제 완료`);
                } catch(e) {
                    alert('삭제 실패: ' + (e.message || e));
                }
            },
        });
    }

    function _escQL(s) { return String(s).replace(/'/g, "\\'").replace(/"/g, '&quot;'); }
    function _escL(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    /* ── Clone 안내 모달 ── */
    /* ── Clone 안내 모달 ── */
    function _cloneModal() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { App._toast('⚠ 저장소 미설정'); return; }
        const cloneUrl = `https://github.com/${vcfg.repo}.git`;

        navigator.clipboard.writeText(cloneUrl).catch(() => {});

        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid rgba(160,144,255,.35);border-radius:12px;
            padding:20px 22px;max-width:460px;width:100%;box-shadow:0 12px 50px rgba(0,0,0,.7)">
          <div style="font-size:13px;font-weight:700;color:#a090ff;margin-bottom:10px">📋 Clone URL 복사됨</div>
          <div style="font-size:11px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
            터미널에서 아래 명령으로 로컬에 Clone하세요:
          </div>
          <div style="background:var(--bg3);border:1px solid var(--bd);border-radius:6px;
              padding:9px 12px;font-family:var(--fm);font-size:11px;color:#a090ff;
              margin-bottom:14px;word-break:break-all;user-select:all">
            git clone ${cloneUrl}
          </div>
          <div style="font-size:10.5px;color:var(--tx3);margin-bottom:14px;line-height:1.6">
            Clone 후 <b style="color:var(--tx2)">로컬 폴더 열기</b>로 해당 폴더를 선택하면<br>
            Pull / Push로 GitHub와 동기화할 수 있습니다.
          </div>
          <div style="background:rgba(247,201,106,.1);border:1px solid rgba(247,201,106,.3);
              border-radius:6px;padding:8px 12px;margin-bottom:14px;
              display:flex;align-items:center;gap:10px">
            <div style="flex:1;font-size:10.5px;color:#f7c96a;line-height:1.6">
              📂 <b>폴더 찾기</b> — 해당 폴더에서 <code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px">cmd</code>를 실행하여 이 코드를 실행하세요 (자동복사됩니다)
            </div>
            <button id="pvs-clone-folder-btn"
                style="padding:5px 12px;border-radius:5px;border:1px solid rgba(247,201,106,.4);
                    background:rgba(247,201,106,.12);color:#f7c96a;font-size:11px;
                    cursor:pointer;white-space:nowrap;flex-shrink:0">
                📂 폴더 찾기</button>
          </div>
          <div style="display:flex;justify-content:flex-end">
            <button id="pvs-clone-close" style="padding:6px 16px;border-radius:6px;
                border:1px solid var(--bd);background:var(--bg3);
                color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
          </div>
        </div>`;
        document.body.appendChild(ov);
        App._toast('📋 Clone URL 복사됨: ' + cloneUrl);

        document.getElementById('pvs-clone-close').onclick = () => ov.remove();
        ov.onclick = e => { if (e.target === ov) ov.remove(); };

        /* 폴더 찾기 — 파일 선택창으로 폴더 열기 */
        document.getElementById('pvs-clone-folder-btn').onclick = () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.webkitdirectory = true;
            input.onchange = () => {
                if (input.files.length) {
                    const path = input.files[0].webkitRelativePath.split('/')[0];
                    App._toast(`📂 폴더 선택됨: ${path} — 로컬 탭에서 이 폴더를 열기하세요`);
                    ov.remove();
                    /* FM의 폴더 선택 연결 */
                    if (typeof FM !== 'undefined') FM.selectFolder();
                }
            };
            input.click();
        };
    }

    /* ── Clone URL 복사 (구형, 하위 호환) ── */
    function _clone() { _cloneModal(); }

    /* ── 새 파일 ── */
    /* ── 탭 분기: 로컬 vs GitHub ── */
    function _dispatchNewFile()   { _activeTab === 'local' ? _pvNewFile()   : _newFile(); }
    function _dispatchNewFolder() { _activeTab === 'local' ? _pvNewFolder() : _newFolder(); }

    /* ══════════════════════════════════════════════════
       PVShare 로컬 폴더 파일/폴더 생성 (FM 방식 차용)
    ══════════════════════════════════════════════════ */

    /* ── 특정 폴더 안에 새 하위 폴더 만들기 (폴더 헤더 📁+ 버튼) ── */
    async function _pvCreateFolderIn(parentPath) {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* parentPath 를 기본 선택한 채 폴더 이름 입력 모달 */
        const folderSet = new Set(['']);