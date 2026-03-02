/* ═══════════════════════════════════════════════════════════
   GitHub API 헬퍼 — GH에서 사용
   cfg: { token, repo }  path: API 경로  opts: fetch 옵션
═══════════════════════════════════════════════════════════ */
window.GHApi = (() => {
    function base(cfg) {
        if (!cfg) return null;
        const [owner, repo] = cfg.repo.split('/');
        return `https://api.github.com/repos/${owner}/${repo}`;
    }

    async function fetch(cfg, path, opts = {}) {
        if (!cfg?.token) throw new Error('토큰이 설정되지 않았습니다');
        const url = path.startsWith('http') ? path : base(cfg) + path;
        const res = await window.fetch(url, {
            ...opts,
            headers: {
                'Authorization': `token ${cfg.token}`,
                'Accept': 'application/vnd.github.v3+json',
                'X-GitHub-Api-Version': '2022-11-28',
                ...(opts.headers || {}),
            },
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(`GitHub API ${res.status}: ${err.message || res.statusText}`);
        }
        return res.json();
    }

    return { base, fetch };
})();
