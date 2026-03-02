        _pvFiles.forEach(f => {
            const parts = (f.folder || '').split('/');
            let acc = '';
            for (const p of parts) { if (!p) continue; acc = acc ? acc + '/' + p : p; folderSet.add(acc); }
            if (f.isDir) folderSet.add(f.path);
        });
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const result = await _pvShowNewFolderModal(parentOptions, parentPath);
        if (!result) return;

        const { parentVal, name } = result;
        if (!name.trim()) return;
        const safe  = name.trim().replace(/[/\\:*?"<>|]/g, '_');
        const where = parentVal ? parentVal + '/' + safe : safe;

        try {
            const parentDirH = await _pvGetDirHandle(parentVal, true);
            const newDirH = await parentDirH.getDirectoryHandle(safe, { create: true });
            /* .gitkeep 생성 */
            try {
                const kh = await newDirH.getFileHandle('.gitkeep', { create: true });
                const kw = await kh.createWritable();
                await kw.write(''); await kw.close();
            } catch(e) {}
            App._toast('📁 "' + where + '" 폴더 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 특정 폴더에 새 파일 만들기 (폴더 헤더 + 버튼) ── */
    async function _pvCreateFileInFolder(folderPath) {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* folderPath 를 기본 위치로 선택한 채 모달 열기 */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            const parts = (f.folder || '').split('/');
            let acc = '';
            for (const p of parts) { if (!p) continue; acc = acc ? acc + '/' + p : p; folderSet.add(acc); }
            if (f.isDir) folderSet.add(f.path);
        });
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        /* 모달 표시 — folderPath 를 기본 선택값으로 */
        const chosen = await _pvShowNewFileModal(folderOptions, folderPath);
        if (!chosen) return;

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe  = fname.replace(/[/\:*?"<>|]/g, '_');
        const where = folderVal ? folderVal + '/' + safe : safe;

        try {
            const destDirH = await _pvGetDirHandle(folderVal, true);
            const fh = await destDirH.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('# ' + safe.replace(/\.md$/i,'') + '\n\n내용을 입력하세요.\n');
            await wr.close();
            App._toast('📄 "' + where + '" 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 파일 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 파일 생성 모달 ── */
    async function _pvNewFile() {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 — 버튼 클릭 직후(사용자 제스처 컨텍스트) */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* 폴더 목록 수집 (isDir 빈 폴더 포함) */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            if (f.folder) folderSet.add(f.folder);
            if (f.isDir)  folderSet.add(f.path);   /* 빈 폴더도 선택 가능 */
        });
        const folderOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            folderOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const chosen = await _pvShowNewFileModal(folderOptions);
        if (!chosen) return;

        const { folderVal, filename } = chosen;
        let fname = filename.trim();
        if (!fname) return;
        if (!/\.[a-z]+$/i.test(fname)) fname += '.md';
        const safe = fname.replace(/[/\\:*?"<>|]/g, '_');
        const where = folderVal ? folderVal + '/' + safe : safe;

        try {
            /* create=true: 대상 폴더가 없으면 생성 */
            const destDirH = await _pvGetDirHandle(folderVal, true);
            const fh = await destDirH.getFileHandle(safe, { create: true });
            const wr = await fh.createWritable();
            await wr.write('# ' + safe.replace(/\.md$/i,'') + '\n\n내용을 입력하세요.\n');
            await wr.close();

            App._toast('📄 "' + where + '" 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 파일 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 폴더 생성 모달 ── */
    async function _pvNewFolder() {
        if (!_pvDirHandle) { App._toast('⚠ 먼저 공개노트 폴더를 선택하세요'); return; }

        /* 권한 선요청 — 버튼 클릭 직후(사용자 제스처 컨텍스트) */
        try {
            const perm = await _pvDirHandle.requestPermission({ mode: 'readwrite' });
            if (perm !== 'granted') { App._toast('⚠ 폴더 쓰기 권한이 필요합니다'); return; }
        } catch(e) { App._toast('⚠ 권한 요청 실패: ' + e.message); return; }

        /* 폴더 목록 수집 (isDir 빈 폴더 포함) */
        const folderSet = new Set(['']);
        _pvFiles.forEach(f => {
            if (f.folder) folderSet.add(f.folder);
            if (f.isDir)  folderSet.add(f.path);   /* 빈 폴더도 상위로 선택 가능 */
        });
        const parentOptions = [{ label: '📁 (루트)', value: '' }];
        [...folderSet].filter(p => p).sort().forEach(p => {
            const depth = (p.match(/\//g) || []).length;
            parentOptions.push({ label: '📂 ' + '  '.repeat(depth) + p.split('/').pop() + '  (' + p + ')', value: p });
        });

        const result = await _pvShowNewFolderModal(parentOptions);
        if (!result) return;

        const { parentVal, name } = result;
        const safe  = name.replace(/[/\\:*?"<>|]/g, '_');
        const where = parentVal ? parentVal + '/' + safe : safe;

        try {
            /* create=true: 부모 경로가 없어도 생성 */
            const parentDirH = await _pvGetDirHandle(parentVal, true);
            const newDirH = await parentDirH.getDirectoryHandle(safe, { create: true });

            /* .gitkeep 생성 (빈 폴더 Git 추적용) */
            try {
                const kh = await newDirH.getFileHandle('.gitkeep', { create: true });
                const kw = await kh.createWritable();
                await kw.write('');
                await kw.close();
            } catch(e) {}

            App._toast('📁 "' + where + '" 폴더 생성됨');
            await _pvSync();
            _renderLocalFiles();
        } catch(e) {
            App._toast('❌ 폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 로컬 새 파일 모달 UI (FM._showNewFileModal 방식 차용) ── */
    function _pvShowNewFileModal(folderOptions, defaultFolder) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-newfile-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-newfile-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9700;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">💻 새 파일 만들기 (로컬)</span>
                    <button id="pvnf-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (저장 폴더)</label>
                    <select id="pvnf-folder" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${folderOptions.map(o => '<option value="' + o.value + '"' + (defaultFolder !== undefined && o.value === defaultFolder ? ' selected' : '') + '>' + o.label + '</option>').join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">파일 이름 (확장자 없으면 .md 자동)</label>
                    <input id="pvnf-name" type="text" value="새파일.md" autocomplete="off"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvnf-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvnf-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('pvnf-name');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvnf-close').onclick   = () => close(null);
            document.getElementById('pvnf-cancel').onclick  = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvnf-ok').onclick = () => {
                const filename  = nameInput.value.trim();
                if (!filename) { nameInput.focus(); return; }
                const folderVal = document.getElementById('pvnf-folder').value;
                close({ folderVal, filename });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('pvnf-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ── 로컬 새 폴더 모달 UI ── */
    function _pvShowNewFolderModal(parentOptions, defaultParent) {
        return new Promise(resolve => {
            const existing = document.getElementById('pvs-newfolder-modal');
            if (existing) existing.remove();

            const ov = document.createElement('div');
            ov.id = 'pvs-newfolder-modal';
            ov.style.cssText = 'position:fixed;inset:0;z-index:9700;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center';

            const box = document.createElement('div');
            box.style.cssText = 'background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:20px 22px;min-width:320px;max-width:420px;width:90%;box-shadow:0 8px 40px rgba(0,0,0,.5)';
            box.innerHTML = `
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:14px;font-weight:700;color:var(--txh)">💻 새 폴더 만들기 (로컬)</span>
                    <button id="pvnd-close" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:18px;line-height:1;padding:0 4px">✕</button>
                </div>
                <div style="margin-bottom:12px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">위치 (부모 폴더)</label>
                    <select id="pvnd-parent" style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:12px;padding:7px 10px;outline:none;cursor:pointer;box-sizing:border-box">
                        ${parentOptions.map(o => '<option value="' + o.value + '">' + o.label + '</option>').join('')}
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:var(--tx3);display:block;margin-bottom:5px">폴더 이름</label>
                    <input id="pvnd-name" type="text" value="새폴더" autocomplete="off"
                        style="width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;padding:7px 10px;outline:none;box-sizing:border-box">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="pvnd-cancel" style="padding:6px 16px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="pvnd-ok" style="padding:6px 18px;border-radius:6px;border:none;background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">✔ 생성</button>
                </div>`;

            ov.appendChild(box);
            document.body.appendChild(ov);

            const nameInput = document.getElementById('pvnd-name');
            setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);

            const close = (v) => { ov.remove(); resolve(v); };
            document.getElementById('pvnd-close').onclick  = () => close(null);
            document.getElementById('pvnd-cancel').onclick = () => close(null);
            ov.onclick = (e) => { if (e.target === ov) close(null); };
            document.getElementById('pvnd-ok').onclick = () => {
                const name = nameInput.value.trim();
                if (!name) { nameInput.focus(); return; }
                const parentVal = document.getElementById('pvnd-parent').value;
                close({ parentVal, name });
            };
            nameInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') document.getElementById('pvnd-ok').click();
                if (e.key === 'Escape') close(null);
            });
        });
    }

    /* ─────────────────────────────────────────────────── */
    /* GitHub 탭 새 파일/폴더 (기존 유지) */
    /* ─────────────────────────────────────────────────── */
    async function _newFile() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const name = prompt('새 파일명 (예: docs/새파일.md):','docs/새파일.md');
        if (!name) return;

        try {
            _setStatus('생성 중…');
            let sha = null;
            try { const ex = await _getFile(name); sha = ex.sha; } catch(e) {}
            await _putFile(name, '# 새 문서\n\n내용을 입력하세요.\n', `Create: ${name}`, sha);
            _setStatus('');
            _loadList();
            App._toast('📄 파일 생성: ' + name);
        } catch(e) {
            _setStatus('오류');
            alert('생성 실패: ' + e.message);
        }
    }

    /* ── 새 폴더 (.gitkeep) ── */
    async function _newFolder() {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) { _showSettings(); return; }

        const name = prompt('새 폴더명 (예: docs/강의자료):','docs/');
        if (!name) return;

        const keepPath = name.replace(/\/$/, '') + '/.gitkeep';
        try {
            _setStatus('생성 중…');
            await _putFile(keepPath, '', `Create folder: ${name}`, null);
            _setStatus('');
            _loadList();
            App._toast('📁 폴더 생성: ' + name);
        } catch(e) {
            _setStatus('오류');
            alert('폴더 생성 실패: ' + e.message);
        }
    }

    /* ── 파일/폴더 삭제 ── */
    async function _deleteItem(btn) {
        const path = btn.dataset.path;
        const type = btn.dataset.type;
        const name = btn.dataset.name;
        const sha  = btn.dataset.sha;

        if (!confirm(`"${name}"을(를) 삭제하시겠습니까?`)) return;

        try {
            _setStatus('삭제 중…');
            if (type === 'dir') {
                /* 폴더: 하위 파일 전체 가져와서 Trees API로 삭제 */
                const items = await _api(`/git/trees/${_loadCfg()?.branch || 'main'}?recursive=1`);
                const tree  = (items.tree || []).filter(f => f.type === 'blob' && f.path.startsWith(path + '/'));
                await _deleteFolderContents(path, tree);
            } else {
                await _deleteFile(path, sha, `Delete: ${name}`);
            }
            _setStatus('');
            _loadList();
            App._toast(`🗑 삭제: ${name}`);
        } catch(e) {
            _setStatus('오류');
            alert('삭제 실패: ' + e.message);
        }
    }

    /* ── 파일/폴더 이동 ── */
    async function _moveFile(btn) {
        const path = btn.dataset.path;
        const type = btn.dataset.type;
        const name = path.split('/').pop();

        const newPath = prompt('이동할 경로 (전체 경로 입력):', path);
        if (!newPath || newPath === path) return;

        try {
            _setStatus('이동 중…');
            if (type === 'dir') {
                App._toast('⚠ 폴더 이동은 지원되지 않습니다. 파일을 직접 이동해 주세요.');
                _setStatus('');
                return;
            }
            /* 파일: 새 경로에 쓰고 기존 경로 삭제 */
            const oldFile = await _getFile(path);
            const content = decodeURIComponent(escape(atob(oldFile.content.replace(/\n/g,''))));
            let newSha = null;
            try { const ex = await _getFile(newPath); newSha = ex.sha; } catch(e) {}
            await _putFile(newPath, content, `Move: ${name} → ${newPath}`, newSha);
            await _deleteFile(path, oldFile.sha, `Move (cleanup): ${name}`);
            _setStatus('');
            _loadList();
            App._toast(`↗ 이동 완료: ${path} → ${newPath}`);
        } catch(e) {
            _setStatus('오류');
            alert('이동 실패: ' + e.message);
        }
    }

    /* ── GH 파일행 📤 버튼에서 직접 push ── */
    async function quickPush({ name, content }) {
        const vcfg = _loadCfg();
        if (!vcfg?.repo) {
            if (confirm('md-viewer 저장소가 설정되지 않았습니다. 지금 설정하시겠습니까?')) {
                _showSettings();
            }
            return;
        }

        const safeName = name.replace(/[^a-zA-Z0-9가-힣._-]/g,'_').replace(/\.md$/i,'') + '.md';

        /* prompt 대신 전용 모달 — 파일명이 항상 보임 */
        return new Promise(resolve => {
            const ov = document.createElement('div');
            ov.style.cssText = 'position:fixed;inset:0;z-index:9350;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:16px';
            ov.innerHTML = `
            <div style="background:var(--bg2);border:1px solid rgba(88,200,248,.3);
                border-radius:14px;padding:22px 24px;max-width:420px;width:100%;
                box-shadow:0 12px 50px rgba(0,0,0,.7)">
                <div style="font-size:13px;font-weight:700;color:#58c8f8;margin-bottom:4px">
                    📤 md-viewer에 Push</div>
                <div style="font-size:11px;color:var(--tx3);margin-bottom:14px">
                    <span style="color:var(--tx2)">${_esc(vcfg.repo)}</span>
                    의 <code style="color:#a090ff">docs/</code> 폴더에 저장됩니다.
                </div>
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:5px">
                    저장 파일명</label>
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:16px">
                    <span style="font-size:12px;color:var(--tx3);flex-shrink:0">docs/</span>
                    <input id="qp-fname" type="text" value="${safeName}"
                        style="flex:1;background:var(--bg3);border:1px solid var(--bd);
                            border-radius:6px;color:var(--tx);font-size:12px;
                            padding:7px 10px;outline:none;box-sizing:border-box"
                        oninput="document.getElementById('qp-preview').textContent=this.value">
                </div>
                <div style="font-size:10px;color:var(--tx3);margin-bottom:14px;
                    padding:7px 10px;background:var(--bg3);border-radius:6px">
                    🔗 예상 링크:
                    <span id="qp-preview" style="color:#a090ff;word-break:break-all;font-family:var(--fm)">
                        ${safeName}
                    </span>
                </div>
                <div id="qp-status" style="font-size:11px;color:#6af7b0;margin-bottom:10px;display:none"></div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="qp-cancel" style="padding:7px 16px;border-radius:6px;
                        border:1px solid var(--bd);background:var(--bg3);
                        color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
                    <button id="qp-ok" style="padding:7px 18px;border-radius:6px;border:none;
                        background:var(--ac);color:#fff;font-size:12px;font-weight:600;cursor:pointer">
                        ⬆ Push</button>
                </div>
            </div>`;
            document.body.appendChild(ov);
            setTimeout(() => {
                const inp = document.getElementById('qp-fname');
                if (inp) { inp.focus(); inp.select(); }
            }, 40);

            const close = () => { ov.remove(); resolve(); };
            document.getElementById('qp-cancel').onclick = close;
            ov.onclick = (e) => { if (e.target === ov) close(); };

            document.getElementById('qp-ok').onclick = async () => {
                const fname = document.getElementById('qp-fname').value.trim();
                if (!fname) { alert('파일명을 입력하세요'); return; }
                const filePath = 'docs/' + fname;
                const okBtn    = document.getElementById('qp-ok');
                const statusEl = document.getElementById('qp-status');

                okBtn.textContent = '⟳ Push 중…'; okBtn.disabled = true;
                statusEl.style.display = '';
                statusEl.textContent = `docs/${fname} 에 저장 중…`;

                try {
                    let sha = null;
                    try { const ex = await _getFile(filePath); sha = ex.sha; } catch(e) {}
                    await _putFile(filePath, content, `Publish: ${fname}`, sha);
                    const link = _makeLink(filePath);
                    statusEl.textContent = '✅ Push 완료!';
                    App._toast('✅ md-viewer Push 완료');
                    setTimeout(() => { ov.remove(); _showLinkResult(link, fname); resolve(); }, 800);
                    /* 관리 창이 열려 있으면 목록 새로고침 */
                    if (document.getElementById('pvs-list')) _loadList('docs');
                } catch(e) {
                    okBtn.textContent = '⬆ Push'; okBtn.disabled = false;
                    statusEl.style.color = '#f76a6a';
                    statusEl.textContent = '❌ ' + e.message;
                }
            };
        });
    }

    /* ── 링크 결과 모달 ── */
    function _showLinkResult(url, title) {
        const ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;inset:0;z-index:9300;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid rgba(106,247,176,.35);
            border-radius:14px;padding:24px 26px;max-width:460px;width:100%;
            box-shadow:0 12px 50px rgba(0,0,0,.7)">
            <div style="font-size:14px;font-weight:700;color:#6af7b0;margin-bottom:6px">
                ✅ 공유 링크 발급 — ${_esc(title)}</div>
            <div style="font-size:11px;color:var(--tx3);margin-bottom:12px">
                링크를 복사해 공유하세요. 문서를 업데이트해도 같은 링크로 최신 내용이 표시됩니다.
            </div>
            <input id="pvsr-url" type="text" readonly value="${url}" onclick="this.select()"
                style="width:100%;background:var(--bg3);border:1px solid var(--bd);
                    border-radius:6px;color:var(--tx);font-size:11px;
                    padding:8px 10px;outline:none;box-sizing:border-box;
                    font-family:var(--fm);margin-bottom:12px">
            <div style="display:flex;gap:8px">
                <button id="pvsr-copy" style="flex:1;padding:9px;border-radius:7px;border:none;
                    background:var(--ac);color:#fff;font-size:13px;font-weight:700;cursor:pointer">
                    📋 링크 복사</button>
                <a href="${url}" target="_blank" rel="noopener noreferrer"
                    style="flex:1;padding:9px;border-radius:7px;
                        border:1px solid rgba(160,144,255,.4);
                        background:rgba(160,144,255,.1);color:#a090ff;
                        font-size:12px;font-weight:600;cursor:pointer;
                        text-decoration:none;display:flex;align-items:center;
                        justify-content:center;gap:4px">
                    🌐 미리보기</a>
                <button id="pvsr-close" style="padding:9px 14px;border-radius:7px;
                    border:1px solid var(--bd);background:var(--bg3);
                    color:var(--tx2);font-size:12px;cursor:pointer">닫기</button>
            </div>
        </div>`;
        document.body.appendChild(ov);
        setTimeout(() => { document.getElementById('pvsr-url')?.select(); }, 40);
        const close = () => ov.remove();
        document.getElementById('pvsr-close').onclick = close;
        ov.onclick = (e) => { if (e.target === ov) close(); };
        document.getElementById('pvsr-copy').onclick = () => {
            navigator.clipboard.writeText(url).then(() => {
                document.getElementById('pvsr-copy').textContent = '✅ 복사됨!';
                setTimeout(close, 1400);
            });
        };
    }

    /* ── 설정 모달 ── */
    /* ── 설정 모달 (로컬 폴더 + md-viewer 저장소 통합) ── */
    function _showSettings() {
        const vcfg      = _loadCfg() || {};
        const curFolder = _pvFolderName || _pvLoadFolderName() || '';

        const ov = document.createElement('div');
        ov.id = 'pvs-settings-overlay';
        ov.style.cssText = 'position:fixed;inset:0;z-index:9400;background:rgba(0,0,0,.78);display:flex;align-items:center;justify-content:center;padding:16px';
        ov.innerHTML = `
        <div style="background:var(--bg2);border:1px solid var(--bd);border-radius:14px;
            padding:0;max-width:460px;width:100%;
            box-shadow:0 12px 50px rgba(0,0,0,.7);overflow:hidden">

          <!-- 헤더 -->
          <div style="display:flex;align-items:center;justify-content:space-between;
              padding:14px 18px 12px;border-bottom:1px solid var(--bd);background:var(--bg3)">
            <span style="font-size:13px;font-weight:700;color:var(--txh)">⚙ 공개노트 설정</span>
            <button id="vcfg-x" style="background:none;border:none;cursor:pointer;
                color:var(--tx3);font-size:18px;padding:0;line-height:1">✕</button>
          </div>

          <div style="padding:18px">

            <!-- ① 로컬 폴더 섹션 -->
            <div style="margin-bottom:18px;padding:12px 14px;
                background:var(--bg3);border:1px solid var(--bd);border-radius:10px">
              <div style="font-size:11px;font-weight:700;color:#58c8f8;margin-bottom:10px;
                  letter-spacing:.5px">💻 로컬 폴더</div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                로컬 PC의 마크다운 폴더를 연결합니다.<br>
                선택한 폴더의 .md 파일이 로컬 탭에 표시됩니다.
              </div>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="flex:1;background:var(--bg4);border:1px solid var(--bd);
                    border-radius:6px;padding:7px 10px;font-size:12px;
                    color:${curFolder ? 'var(--tx)' : 'var(--tx3)'};
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                    id="vcfg-folder-display">
                  ${curFolder ? '📂 ' + curFolder : '선택된 폴더 없음'}
                </div>
                <button id="vcfg-select-folder"
                    style="padding:7px 14px;border-radius:6px;white-space:nowrap;
                        border:1px solid rgba(88,200,248,.4);
                        background:rgba(88,200,248,.1);color:#58c8f8;
                        font-size:12px;cursor:pointer;flex-shrink:0">
                  ${curFolder ? '📂 변경' : '📂 폴더 선택'}
                </button>
              </div>
            </div>

            <!-- ② md-viewer 저장소 섹션 -->
            <div style="margin-bottom:14px;padding:12px 14px;
                background:var(--bg3);border:1px solid var(--bd);border-radius:10px">
              <div style="font-size:11px;font-weight:700;color:#a090ff;margin-bottom:8px;
                  letter-spacing:.5px">🐙 md-viewer GitHub 저장소</div>
              <div style="font-size:10.5px;color:var(--tx3);margin-bottom:10px;line-height:1.6">
                노트를 공개할 GitHub 저장소를 설정합니다.<br>
                토큰은 GH 패널 설정에서 자동으로 가져옵니다.
              </div>
              <div style="margin-bottom:10px">
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:4px">
                  저장소 (owner/repo)</label>
                <input id="vcfg-repo" type="text" value="${vcfg.repo || ''}"
                    placeholder="예: myname/my-notes"
                    style="width:100%;background:var(--bg4);border:1px solid var(--bd);
                        border-radius:6px;color:var(--tx);font-size:12px;
                        padding:7px 10px;outline:none;box-sizing:border-box">
                <div style="font-size:10px;color:var(--tx3);margin-top:4px">
                  현재: <span style="color:#a090ff">${vcfg.repo || '미설정'}</span>
                </div>
              </div>
              <div>
                <label style="font-size:10px;color:var(--tx3);display:block;margin-bottom:4px">
                  기본 브랜치</label>
                <input id="vcfg-branch" type="text" value="${vcfg.branch || 'main'}"
                    placeholder="main"
                    style="width:100%;background:var(--bg4);border:1px solid var(--bd);
                        border-radius:6px;color:var(--tx);font-size:12px;
                        padding:7px 10px;outline:none;box-sizing:border-box">
              </div>
            </div>

            <!-- 버튼 -->
            <div style="display:flex;gap:8px;justify-content:flex-end">
              <button id="vcfg-cancel" style="padding:7px 16px;border-radius:6px;
                  border:1px solid var(--bd);background:var(--bg3);
                  color:var(--tx2);font-size:12px;cursor:pointer">취소</button>
              <button id="vcfg-save" style="padding:7px 20px;border-radius:6px;
                  border:none;background:var(--ac);color:#fff;
                  font-size:12px;font-weight:600;cursor:pointer">저장</button>
            </div>

          </div>
        </div>`;

        document.body.appendChild(ov);
        const close = () => ov.remove();

        document.getElementById('vcfg-x').onclick      = close;
        document.getElementById('vcfg-cancel').onclick  = close;
        ov.onclick = (e) => { if (e.target === ov) close(); };

        /* ── 로컬 폴더 선택 버튼 ── */
        document.getElementById('vcfg-select-folder').onclick = async () => {
            const ok = await _pvSelectFolder();
            if (!ok) return;
            const newFolder = _pvFolderName;
            const dispEl    = document.getElementById('vcfg-folder-display');
            const btnEl     = document.getElementById('vcfg-select-folder');
            if (dispEl) {
                dispEl.textContent = newFolder ? '📂 ' + newFolder : '선택된 폴더 없음';
                dispEl.style.color = newFolder ? 'var(--tx)' : 'var(--tx3)';
            }
            if (btnEl) btnEl.textContent = newFolder ? '📂 변경' : '📂 폴더 선택';
            /* 로컬 탭 폴더바도 즉시 업데이트 */
            _renderLocalFiles();
        };

        /* ── 저장 버튼 ── */
        document.getElementById('vcfg-save').onclick = () => {
            const repo   = document.getElementById('vcfg-repo').value.trim();
            const branch = document.getElementById('vcfg-branch').value.trim() || 'main';
            if (repo && !repo.includes('/')) {
                App._toast('⚠ 저장소명은 owner/repo 형식으로 입력하세요');
                return;
            }
            if (repo) {
                _saveCfg({ repo, branch });
                /* 모달 헤더 저장소명 업데이트 */
                const nameEl = document.getElementById('pvs-repo-name');
                if (nameEl) {
                    nameEl.textContent = repo + ' ↗';
                    nameEl.href = `https://github.com/${repo}`;
                }
                App._toast('✅ md-viewer 저장소 설정 저장됨');
            }
            close();
            _loadList();
            /* 로컬 탭도 새로고침 */
            const localBtn = document.getElementById('pvs-tab-local');
            if (localBtn && localBtn.style.color && localBtn.style.color !== 'var(--tx3)') {
                _renderLocalFiles();
            }
        };

        setTimeout(() => { document.getElementById('vcfg-repo')?.focus(); }, 50);
    }

    /* ── 공개노트 로컬 폴더 선택 (PVShare 전용) ── */
    async function _selectLocalFolder() {
        const ok = await _pvSelectFolder();
        if (ok) _renderLocalFiles();
    }

    /* ── 로컬 파일 열기 (PVShare 전용 → _pvOpenFile 위임) ── */
    function _openLocalFile(btnOrRow) { _pvOpenFile(btnOrRow); }

    /* ── 로컬 파일 Push (PVShare 전용 → _pvPushPublic 위임) ── */
    async function _pushLocalFile(btn) { await _pvPushPublic(btn); }

    /* ── 초기화 ── */
    function refresh() {
        const btn = document.getElementById(BTN_ID);
        if (!btn) return;
        const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
        btn.style.display = tab ? '' : 'none';
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', refresh);
    } else {
        setTimeout(refresh, 300);
    }

    return {
        refresh,
        copy       : openModal,
        openModal,
        quickPush,
        quickPushCurrent: () => {
            const tab = (typeof TM !== 'undefined') ? TM.getActive() : null;
            if (!tab) { App._toast('⚠ 열린 문서가 없습니다'); return; }
            const content = document.getElementById('editor')?.value || '';
            return quickPush({ name: tab.title || 'document', content });
        },
        _refresh,
        _pull,
        _pushCurrent,
        _clone,
        _cloneModal,
        _switchTab,
        _newFile,
        _newFolder,
        _dispatchNewFile,
        _dispatchNewFolder,
        _pvNewFile,
        _pvNewFolder,
        _deleteItem,
        _moveFile,
        _copyLink,
        _search,
        _itemClick,
        _showSettings,
        _selectLocalFolder,
        _pvOpenLocalDir,
        _pvCreateFolderIn,
        _pvCreateFileInFolder,
        _openLocalFile,
        _pushLocalFile,
        _pvSelectFolder,
        _pvRefresh,
        _pvOpenFile,
        _pvPushPrivate,
        _pvPushPublic,
        _pvMoveFile,
        _pvDeleteFile,
        _loadList,
        _toggleAutoRefresh,
        _showArIntervalSetting,
    };
})();
