/* A4Ruler — 미리보기 A4 페이지 구분 점선 (297mm 간격) */
const A4Ruler = (() => {
    let on = false;
    const LINE_CLASS = 'a4-rl';
    const LABEL_CLASS = 'a4-rl-label';

    function getA4Px(page) {
        const MM = 96 / 25.4;
        const cssW = 210 * MM;
        const renderW = page.getBoundingClientRect().width;
        const scale = renderW / cssW;
        return Math.round(297 * MM * scale);
    }

    function drawPage(page) {
        page.querySelectorAll('.' + LINE_CLASS).forEach(el => el.remove());
        if (!on) return;

        const pageH = page.getBoundingClientRect().height;
        const gap = getA4Px(page);
        let n = 1;
        while (n * gap < pageH - 2) {
            const cssH = page.offsetHeight;
            const scale = pageH / cssH;
            const topCss = Math.round((n * gap) / scale);

            const line = document.createElement('div');
            line.className = LINE_CLASS;
            line.style.top = topCss + 'px';

            const label = document.createElement('span');
            label.className = LABEL_CLASS;
            label.textContent = (297 * n) + ' mm';
            line.appendChild(label);

            page.appendChild(line);
            n++;
        }
    }

    function drawAll() {
        const pages = document.querySelectorAll('#preview-container .preview-page');
        pages.forEach(drawPage);
    }

    function clearAll() {
        document.querySelectorAll('#preview-container .' + LINE_CLASS).forEach(el => el.remove());
    }

    return {
        toggle() {
            on = !on;
            const btn = el('a4-ruler-btn');
            btn.classList.toggle('active', on);
            btn.textContent = on ? '📄 A4 ✓' : '📄 A4';
            if (on) drawAll();
            else clearAll();
        },
        refresh() {
            if (!on) return;
            requestAnimationFrame(() => drawAll());
        },
    };
})();
