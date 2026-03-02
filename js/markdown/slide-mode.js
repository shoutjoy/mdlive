/* Slide Mode 토글 + ScholarSlide 연동 — PR, App 의존 */
window.SlideMode = {
    toggle() {
        const next = !PR.getSlideMode();
        PR.setSlideMode(next);
        if (typeof App !== 'undefined' && App.render) App.render();
        const btn = document.getElementById('slide-mode-btn');
        if (btn) btn.classList.toggle('active', next);
    },
    openInScholarSlide() {
        const ed = typeof el === 'function' ? el('editor') : document.getElementById('editor');
        const md = ed ? ed.value : '';
        const encoded = encodeURIComponent(md);
        window.open(`scholarslide.html?data=${encoded}`, '_blank', 'noopener');
    }
};
