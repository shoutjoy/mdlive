/* ═══════════════════════════════════════════════════════════
   GitHub 커밋 히스토리 — GH에서 사용
   의존: GHApi (api.js), IDB mdpro-gh-v1 meta
═══════════════════════════════════════════════════════════ */
window.GHHistory = (() => {
    const GH_DB = 'mdpro-gh-v1';
    let _db = null;
    let _cache = [];

    function _esc(s) {
        if (s == null) return '';
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    }

    function _getDB() {
        if (_db) return Promise.resolve(_db);
        return new Promise((res, rej) => {
            const req = indexedDB.open(GH_DB, 1);
            req.onupgradeneeded = ev => {
                const db = ev.target.result;
                if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta');
            };
            req.onsuccess = ev => { _db = ev.target.result; res(_db); };
            req.onerror = ev => rej(ev.target.error);
        });
    }

    async function _getMeta(key) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction('meta', 'readonly').objectStore('meta').get(key);
            req.onsuccess = ev => res(ev.target.result ?? null);
            req.onerror = ev => rej(ev.target.error);
        });
    }
    async function _putMeta(key, val) {
        const db = await _getDB();
        return new Promise((res, rej) => {
            const req = db.transaction('meta', 'readwrite').objectStore('meta').put(val, key);
            req.onsuccess = () => res();
            req.onerror = ev => rej(ev.target.error);
        });
    }

    async function loadHistory(cfg, forceRefresh) {
        if (!cfg || typeof GHApi === 'undefined') { alert('GitHub 연결 필요'); return; }
        const repoEl = document.getElementById('gh-history-repo');
        const listEl = document.getElementById('gh-history-list');
        if (repoEl) repoEl.textContent = cfg.repo;

        if (!forceRefresh) {
            try {
                const cached = await _getMeta('gh_hist_' + cfg.repo);
                if (cached && cached.commits && cached.commits.length) {
                    _cache = cached.commits;
                    _renderHistory(_cache);
                    _fetchHistory(cfg).catch(() => {});
                    return;
                }
            } catch (e) {}
        }
        if (listEl) listEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--tx3);font-size:12px">⟳ 로딩 중…</div>';
        await _fetchHistory(cfg);
    }

    async function _fetchHistory(cfg) {
        const data = await GHApi.fetch(cfg, `/commits?sha=${cfg.branch || 'main'}&per_page=60`);
        _cache = data.map(c => ({
            sha: c.sha.slice(0, 7),
            fullSha: c.sha,
            msg: c.commit.message.split('\n')[0],
            author: c.commit.author.name,
            date: c.commit.author.date,
            device: (c.commit.message.match(/\[device:([^\]]+)\]/) || [])[1] || null,
            url: c.html_url,
        }));
        await _putMeta('gh_hist_' + cfg.repo, { commits: _cache, at: Date.now() });
        _renderHistory(_cache);
    }

    function refreshHistory(cfg) { return loadHistory(cfg, true); }

    function filterHistory(q) {
        const filtered = q
            ? _cache.filter(c =>
                c.msg.toLowerCase().includes(q.toLowerCase()) ||
                c.author.toLowerCase().includes(q.toLowerCase()) ||
                c.sha.includes(q))
            : _cache;
        _renderHistory(filtered);
    }

    function _renderHistory(list) {
        const el2 = document.getElementById('gh-history-list');
        const countEl = document.getElementById('gh-history-count');
        if (!el2) return;
        if (countEl) countEl.textContent = `총 ${list.length}개`;
        if (!list.length) {
            el2.innerHTML = '<div style="padding:16px;text-align:center;color:var(--tx3);font-size:12px">커밋이 없습니다</div>';
            return;
        }
        el2.innerHTML = '';
        list.forEach(c => {
            const div = document.createElement('div');
            div.className = 'commit-item';
            const d = new Date(c.date);
            const ds = `${String(d.getMonth() + 1).padStart(2, '0')}.${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
            div.innerHTML =
                `<span class="commit-sha">${_esc(c.sha)}</span>` +
                `<div class="commit-msg">${_esc(c.msg)}` +
                (c.device ? ` <span class="commit-device-badge">📱${_esc(c.device)}</span>` : '') +
                `</div>` +
                `<div class="commit-meta">${_esc(c.author)}<br>${ds}</div>`;
            div.onclick = () => window.open(c.url, '_blank');
            el2.appendChild(div);
        });
    }

    return { loadHistory, refreshHistory, filterHistory, _renderHistory };
})();
