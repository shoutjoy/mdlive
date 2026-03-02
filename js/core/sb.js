/* SB — Sidebar Tab Controller (FM, GH 의존) */
/* ═══════════════════════════════════════════════════════════
   SB — Sidebar Tab Controller  (TOC ↔ FILES 전환)
═══════════════════════════════════════════════════════════ */
const SB = (() => {
    let current = 'toc';
    let source  = localStorage.getItem('mdpro_files_src') || 'local'; // 'local' | 'github'

    function switchTab(id) {
        current = id;
        document.querySelectorAll('.sb-tab').forEach(b =>
            b.classList.toggle('active', b.id === `sb-tab-${id}`));
        document.querySelectorAll('.sb-panel').forEach(p =>
            p.classList.toggle('active', p.id === `sb-panel-${id}`));
        if (id === 'files') {
            _applySource(source);
            if (source === 'local')  FM._render();
            if (source === 'github') GH._render();
        }
    }

    function switchSource(src) {
        source = src;
        localStorage.setItem('mdpro_files_src', src);
        _applySource(src);
        if (src === 'local')  FM._render();
        if (src === 'github') GH._render();
    }

    function _applySource(src) {
        document.querySelectorAll('.fsrc-tab').forEach(b =>
            b.classList.toggle('active', b.id === `fsrc-${src}`));
        document.querySelectorAll('.files-sub').forEach(p =>
            p.classList.toggle('active', p.id === `files-sub-${src}`));
    }

    function init() { _applySource(source); }

    return { switchTab, switchSource, init, currentSource: () => source };
})();
