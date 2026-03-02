/* ═══════════════════════════════════════════════════════════
   탭 세션 영속화 — TM에서 사용
   키: mdpro_tabs_v1  /  payload: { tabs: [{id,title,content,filePath,fileType}], activeId, nextId }
═══════════════════════════════════════════════════════════ */
const Persist = (() => {
    const STORE_KEY = 'mdpro_tabs_v1';

    function save(tabs, activeId, nextId) {
        try {
            const payload = {
                tabs: tabs.map(t => ({
                    id: t.id,
                    title: t.title,
                    content: t.content,
                    filePath: t.filePath ?? null,
                    fileType: t.fileType || 'md'
                })),
                activeId,
                nextId
            };
            localStorage.setItem(STORE_KEY, JSON.stringify(payload));
        } catch (e) {}
    }

    function load() {
        try {
            const raw = localStorage.getItem(STORE_KEY);
            if (!raw) return null;
            const d = JSON.parse(raw);
            if (!d || !d.tabs || !d.tabs.length) return null;
            return {
                tabs: d.tabs,
                activeId: d.activeId,
                nextId: d.nextId || d.tabs.length + 1
            };
        } catch (e) {
            return null;
        }
    }

    return { KEY: STORE_KEY, save, load };
})();
