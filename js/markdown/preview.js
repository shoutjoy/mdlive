/* ═══════════════════════════════════════════════════════════
   PREVIEW RENDERER (PR) — 미리보기 슬라이드/페이지 렌더
   의존: el (dom.js), splitPages, parseSlideContent, mdRender (parser.js), SS, A4Ruler, PV (전역, 로드 순서상 이후 정의 가능)
═══════════════════════════════════════════════════════════ */
const PR = {
    rm: false,
    slideMode: false,
    getSlideMode() { try { return localStorage.getItem('mdpro_slide_mode') === '1'; } catch(e) { return false; } },
    setSlideMode(v) { try { localStorage.setItem('mdpro_slide_mode', v ? '1' : '0'); } catch(e) {} this.slideMode = !!v; },
    /* 단락(p)에만 연속 번호 삽입 — 제목·표·코드·인용 제외 */
    _applyRM(container) {
        /* 기존 번호 제거 */
        container.querySelectorAll('.rm-ln').forEach(n => n.remove());
        if (!this.rm) return;
        let n = 1;
        container.querySelectorAll('.preview-page').forEach(page => {
            /* 직계 p만 대상 (blockquote>p, li>p 등 중첩 제외) */
            page.querySelectorAll(':scope>p, :scope>section>p').forEach(p => {
                const span = document.createElement('span');
                span.className = 'rm-ln';
                span.textContent = n++;
                span.setAttribute('aria-hidden', 'true');
                p.insertBefore(span, p.firstChild);
            });
        });
    },
    render(md, showFootnotes) {
        if (showFootnotes === undefined) showFootnotes = true;
        this.slideMode = this.getSlideMode();
        const c = el('preview-container');
        c.classList.toggle('slide-mode', !!this.slideMode);
        const savedScrollTop = (typeof SS !== 'undefined' && !SS.isEnabled()) ? c.scrollTop : -1;
        const pages = splitPages(md); c.innerHTML = '';
        if (this.slideMode) {
            pages.forEach((p, i) => {
                const parsed = parseSlideContent(p);
                const slideDiv = document.createElement('div');
                slideDiv.className = 'ppt-slide' + (parsed.bullets.length > 6 ? ' slide-bullet-warn' : '');
                slideDiv.dataset.slideIndex = i + 1;
                const inner = document.createElement('div');
                inner.className = 'slide-inner';
                inner.innerHTML = mdRender(p, showFootnotes);
                slideDiv.appendChild(inner);
                const numSpan = document.createElement('span');
                numSpan.className = 'slide-num';
                numSpan.textContent = String(i + 1);
                slideDiv.appendChild(numSpan);
                if (parsed.bullets.length > 6) {
                    const warn = document.createElement('span');
                    warn.className = 'slide-bullet-warn-msg';
                    warn.textContent = '⚠ bullet 6개 초과';
                    slideDiv.appendChild(warn);
                }
                slideDiv.querySelectorAll('a').forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer'; });
                c.appendChild(slideDiv);
            });
            requestAnimationFrame(() => {
                c.querySelectorAll('.ppt-slide .slide-inner').forEach(elm => {
                    if (elm.scrollHeight > elm.clientHeight) elm.parentElement.classList.add('slide-overflow');
                });
            });
            const pgEl = el('pg-cnt'); if (pgEl) pgEl.textContent = pages.length ? `1 / ${pages.length}` : '0 / 0';
        } else {
            pages.forEach((p, i) => {
                const div = document.createElement('div');
                div.className = 'preview-page' + (this.rm ? ' rm' : ''); div.dataset.page = i + 1;
                div.innerHTML = mdRender(p, showFootnotes);
                div.querySelectorAll('a').forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer' });
                c.appendChild(div);
            });
            this._applyRM(c);
            const pgEl = el('pg-cnt'); if (pgEl) pgEl.textContent = `1 / ${pages.length}`;
        }
        if (window.MathJax && typeof MathJax.typesetPromise === 'function') { try { MathJax.typesetPromise([c]).catch(() => {}); } catch(e) {} }
        /* 스크롤 시 현재 페이지 번호 실시간 업데이트 */
        const _pcEl = el('preview-container');
        if (_pcEl && !_pcEl._pgScrollBound) {
            _pcEl._pgScrollBound = true;
            _pcEl.addEventListener('scroll', () => {
                const sel = _pcEl.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
                const scrollPages = [..._pcEl.querySelectorAll(sel)];
                if (!scrollPages.length) return;
                const mid = _pcEl.scrollTop + _pcEl.clientHeight * 0.3;
                let cur = 0;
                for (let i = 0; i < scrollPages.length; i++) {
                    if (scrollPages[i].offsetTop <= mid) cur = i;
                }
                const pgEl = el('pg-cnt'); if (pgEl) pgEl.textContent = `${cur + 1} / ${scrollPages.length}`;
            }, { passive: true });
        }
        if (typeof A4Ruler !== 'undefined') A4Ruler.refresh();
        if (typeof PV !== 'undefined') PV.refresh();
        const slideBtn = document.getElementById('slide-mode-btn');
        if (slideBtn) slideBtn.classList.toggle('active', !!this.slideMode);
        /* sync OFF일 때 저장했던 scrollTop 복원 */
        if (savedScrollTop >= 0) {
            requestAnimationFrame(() => { c.scrollTop = savedScrollTop; });
        }
    }
};
