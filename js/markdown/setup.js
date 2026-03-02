/* ═══════════════════════════════════════════════════════════
   MARKED SETUP — links new tab, heading id (TOC 호환)
   의존: marked (전역, CDN 로드 후)
═══════════════════════════════════════════════════════════ */
(function () {
    if (typeof marked === 'undefined') return;
    marked.setOptions({ breaks: true, gfm: true });
    const _r = new marked.Renderer();
    _r.heading = (text, level) => {
        const plain = text
            .replace(/<[^>]+>/g, '')
            .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&[a-z]+;/g, '')
            .trim();
        const id = 'h-' + plain.toLowerCase()
            .replace(/[^a-z0-9가-힣\s]/g, '')
            .replace(/\s+/g, '-')
            .substring(0, 50);
        return `<h${level} id="${id}">${text}</h${level}>`;
    };
    _r.link = (href, title, text) => `<a href="${href}"${title ? ` title="${title}"` : ''} target="_blank" rel="noopener noreferrer">${text}</a>`;
    marked.use({ renderer: _r });
})();
