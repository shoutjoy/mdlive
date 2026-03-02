/* PV — 미리보기 확대/축소 + PPT 모드 (el, PR 의존) */

/* ═══════════════════════════════════════════════════════════
   PV — 미리보기 확대/축소 + PPT 모드
   PPT 모드: 245% 확대 + scroll-snap으로 페이지 단위 이동
   ↑↓ 키, ◀▶ 버튼으로 페이지 이동
═══════════════════════════════════════════════════════════ */
const PV = (() => {
    let scale = 1.0;
    const STEP = 0.15, MIN = 0.4, MAX = 3.0;
    let pptOn = false;
    let pptIdx = 0;
    let _keyBound = false;

    let _pvFontPt = 11; /* 내부 PV 폰트 크기(pt) */
    let _transOn = false; /* 가로/세로 전환 상태 */

    function setScale(s) {
        scale = Math.min(MAX, Math.max(MIN, Math.round(s * 100) / 100));
        const pc = el('preview-container');
        pc.style.setProperty('--pv-scale', scale);
        el('pv-zoom-lbl').textContent = Math.round(scale * 100) + '%';
        const fontPx = Math.round(_pvFontPt * (96 / 72));
        /* 슬라이드 모드: .ppt-slide 영역에 폰트 크기만 적용 (확대/축소는 폰트로) */
        if (pc.classList.contains('slide-mode')) {
            pc.style.fontSize = fontPx + 'px';
            pc.querySelectorAll('.ppt-slide').forEach(slide => {
                if (scale === 1) {
                    slide.style.transform = '';
                    slide.style.transformOrigin = '';
                    slide.style.marginBottom = '';
                } else {
                    slide.style.transformOrigin = 'top center';
                    slide.style.transform = `scale(${scale})`;
                    const baseH = slide.offsetHeight;
                    slide.style.marginBottom = (16 + baseH * (scale - 1)) + 'px';
                }
            });
            _updateFontLbl();
            return;
        }
        pc.querySelectorAll('.preview-page').forEach(p => {
            if (scale === 1) {
                p.style.transform = ''; p.style.transformOrigin = ''; p.style.marginBottom = '';
            } else {
                p.style.transformOrigin = 'top center';
                p.style.transform = `scale(${scale})`;
                const baseH = p.offsetHeight;
                p.style.marginBottom = (16 + baseH * (scale - 1)) + 'px';
            }
            p.style.fontSize = fontPx + 'px';
            p.style.lineHeight = '1.8'; /* 폰트 변경 시 줄간격 유지 */
        });
        _updateFontLbl();
    }

    function _updateFontLbl() {
        const lbl = el('pv-font-lbl');
        if (lbl) lbl.textContent = _pvFontPt + 'pt';
    }

    function fontUp() {
        _pvFontPt = Math.min(24, _pvFontPt + 1);
        if (pptOn) {
            const pane = el('preview-pane');
            const vw = pane.clientWidth;
            const ratio = vw / Math.round(210 * (96 / 25.4));
            const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
            const pc = el('preview-container');
            const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
            pc.querySelectorAll(sel).forEach(p => {
                p.style.fontSize = fontPx + 'px'; p.style.lineHeight = '1.8';
            });
        } else { setScale(scale); }
        _updateFontLbl();
    }
    function fontDown() {
        _pvFontPt = Math.max(6, _pvFontPt - 1);
        if (pptOn) {
            const pane = el('preview-pane');
            const vw = pane.clientWidth;
            const ratio = vw / Math.round(210 * (96 / 25.4));
            const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
            const pc = el('preview-container');
            const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
            pc.querySelectorAll(sel).forEach(p => {
                p.style.fontSize = fontPx + 'px'; p.style.lineHeight = '1.8';
            });
        } else { setScale(scale); }
        _updateFontLbl();
    }

    /* 미리보기 패널 너비에 맞게 자동 fit */
    function fitToPane() {
        const pc = el('preview-container');
        const pages = [...pc.querySelectorAll('.preview-page')];
        if (!pages.length) return;
        const origW = pages[0].offsetWidth / scale; /* 현재 scale 제거한 원본 너비 */
        const avail = pc.clientWidth - 32;          /* 좌우 패딩 감안 */
        if (avail <= 0) return;
        const fit = Math.floor((avail / origW) * 100) / 100;
        setScale(Math.max(MIN, Math.min(MAX, fit)));
    }

    /* PPT 모드 전용 zoom: 페이지 width/padding/minHeight 비례 조정 */
    function _pptZoom(delta) {
        const pane = el('preview-pane');
        const pc = el('preview-container');
        const pages = getPages();
        if (!pages.length) return;
        const MM = 96 / 25.4;
        const baseWmm = _transOn ? 297 : 210;
        const baseHmm = _transOn ? 210 : 297;
        const origPx = Math.round(baseWmm * MM);
        /* 현재 pane 너비를 기준으로 ratio 산출 후 delta 적용 */
        const curW = parseFloat(pages[0].style.width) || pane.clientWidth;
        const newW = Math.round(Math.max(pane.clientWidth * 0.5,
            Math.min(pane.clientWidth * 2.0, curW + delta * origPx)));
        const ratio = newW / origPx;
        const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
        pages.forEach(p => {
            p.style.width = newW + 'px';
            p.style.padding = Math.round(22 * MM * ratio) + 'px ' + Math.round(18 * MM * ratio) + 'px';
            p.style.minHeight = Math.round(baseHmm * MM * ratio) + 'px';
            p.style.fontSize = fontPx + 'px';
            p.style.lineHeight = '1.8';
        });
        el('pv-zoom-lbl').textContent = Math.round(ratio * 100) + '%';
    }

    function zoomIn() { if (pptOn) { _pptZoom(+STEP); } else { setScale(scale + STEP); } }
    function zoomOut() { if (pptOn) { _pptZoom(-STEP); } else { setScale(scale - STEP); } }

    /* PPT 모드 */
    function getPages() {
        const pc = el('preview-container');
        const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
        return [...pc.querySelectorAll(sel)];
    }

    function pptGo(idx) {
        const pages = getPages();
        if (!pages.length) return;
        pptIdx = Math.max(0, Math.min(pages.length - 1, idx));
        /* PPT 모드: preview-container 스크롤 (scrollIntoView는 부모가 overflow:auto일 때 정확히 작동) */
        const pc = el('preview-container');
        const target = pages[pptIdx];
        pc.scrollTo({ top: target.offsetTop, behavior: 'smooth' });
        el('ppt-pg').textContent = `${pptIdx + 1} / ${pages.length}`;
    }

    /* PPT 뷰포트 단위 이동 (내부 패널용) */
    function pptStep(dir) {
        const pc = el('preview-container');
        const vh = pc.clientHeight;
        let next = pc.scrollTop + dir * vh;
        next = Math.max(0, next);
        /* 페이지 상단 snap */
        getPages().forEach(p => {
            if (Math.abs(next - p.offsetTop) < vh * 0.18) next = p.offsetTop;
        });
        next = Math.min(next, pc.scrollHeight - pc.clientHeight);
        pc.scrollTo({ top: next, behavior: 'smooth' });
        /* 페이지 번호 갱신 */
        setTimeout(() => {
            const mid = pc.scrollTop + vh / 2;
            let best = 0, bestD = Infinity;
            getPages().forEach((p, i) => {
                const d = Math.abs(p.offsetTop + p.offsetHeight / 2 - mid);
                if (d < bestD) { bestD = d; best = i; }
            });
            pptIdx = best;
            el('ppt-pg').textContent = `${best + 1} / ${getPages().length}`;
        }, 350);
    }

    function pptPrev() { pptOn ? pptStep(-1) : pptGo(pptIdx - 1); }
    function pptNext() { pptOn ? pptStep(1) : pptGo(pptIdx + 1); }

    function togglePPT() {
        pptOn = !pptOn;
        const pane = el('preview-pane');
        const btn = el('ppt-btn');
        const nav = el('ppt-nav');

        if (pptOn) {
            /* PPT 진입:
               1. View 모드로 자동 전환 (미리보기 패널 최대화)
               2. transform 대신 width를 패널 너비에 맞게 직접 확대
               3. pv-hdr 항상 위에 유지 */
            App.setView('preview');

            pane.classList.add('ppt-mode');
            btn.textContent = '🎬 종료';
            btn.style.background = 'rgba(240,192,96,.28)';
            btn.style.color = '#ffe090';
            btn.style.borderColor = '#f0c060';
            nav.classList.add('vis');

            /* 패널이 렌더 완료된 뒤 fit 적용 */
            setTimeout(() => {
                const pages = getPages();
                if (!pages.length) return;
                /* 패널 내용 영역 너비 (pv-hdr 너비 = pane 너비) */
                const vw = pane.clientWidth;
                const MM = 96 / 25.4;
                const baseWmm = _transOn ? 297 : 210;
                const baseHmm = _transOn ? 210 : 297;
                const origPx = Math.round(baseWmm * MM); /* A4 가로(mm) 기준 px */
                const ratio = vw / origPx;
                const pc = el('preview-container');

                pages.forEach(p => {
                    p.style.transform = 'none';
                    p.style.transformOrigin = '';
                    p.style.width = vw + 'px';
                    p.style.padding = Math.round(22 * MM * ratio) + 'px ' + Math.round(18 * MM * ratio) + 'px';
                    p.style.minHeight = Math.round(baseHmm * MM * ratio) + 'px';
                    p.style.marginBottom = '0';
                    p.style.boxSizing = 'border-box';
                });
                /* preview-container 폰트 비례 확대 (_pvFontPt 반영) */
                const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
                pages.forEach(p => { p.style.fontSize = fontPx + 'px'; p.style.lineHeight = '1.8'; });
                el('pv-zoom-lbl').textContent = Math.round(ratio * 100) + '%';

                pptIdx = 0;
                pc.scrollTop = 0;
                setTimeout(() => pptGo(0), 60);
            }, 80);

            if (!_keyBound) {
                _keyBound = true;
                document.addEventListener('keydown', _pptKey, true);
            }
        } else {
            /* PPT 종료: 스타일 복구 */
            const drawExt = document.getElementById('pv-draw-ext');
            if (drawExt) drawExt.style.display = 'none';
            pane.classList.remove('ppt-mode');
            btn.textContent = '🎬 PPT';
            btn.style.background = '';
            btn.style.color = '';
            btn.style.borderColor = '';
            nav.classList.remove('vis');

            const pc = el('preview-container');
            getPages().forEach(p => {
                p.style.transform = ''; p.style.transformOrigin = '';
                p.style.width = ''; p.style.padding = '';
                p.style.minHeight = ''; p.style.marginBottom = '';
                p.style.boxSizing = ''; p.style.fontSize = ''; p.style.lineHeight = '';
            });
            pc.style.fontSize = '';
            setScale(1.0);
        }
    }

    /* capture 단계에서 잡아야 에디터/다른 요소 포커스에 무관하게 작동 */
    function _pptKey(e) {
        if (!pptOn) return;
        if (e.key === 'ArrowDown' || e.key === 'PageDown') { e.preventDefault(); e.stopPropagation(); pptNext(); }
        else if (e.key === 'ArrowUp' || e.key === 'PageUp') { e.preventDefault(); e.stopPropagation(); pptPrev(); }
        else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); togglePPT(); }
        else if (e.key >= '1' && e.key <= '6') { e.preventDefault(); IPPT.handleKey(e.key); }
    }

    /* ── Trans (가로/세로 전환) ── */
    function toggleTrans() {
        _transOn = !_transOn;
        const btn = el('pv-trans-btn');
        document.body.classList.toggle('trans-mode', _transOn);
        if (btn) {
            btn.textContent = _transOn ? '↕ Portrait' : '↔ Trans';
        }
        /* 레이아웃이 바뀌므로 약간의 지연 후 다시 맞춤 */
        setTimeout(() => {
            const pc = el('preview-container');
            if (pptOn) {
                refresh();
            } else if (pc.classList.contains('slide-mode')) {
                /* 슬라이드 모드: 폰트/스케일만 재적용 */
                pc.style.fontSize = Math.round(_pvFontPt * (96 / 72)) + 'px';
                _updateFontLbl();
                if (scale !== 1.0) setScale(scale);
            } else {
                if (scale !== 1.0) setScale(scale);
                else fitToPane();
            }
        }, 80);
    }

    /* ── Dark 테마 ── */
    const PV_DARK_KEY = 'mdpro_pv_dark';
    let _darkOn = false;

    function setDark(on) {
        _darkOn = !!on;
        const pc = el('preview-container');
        const btn = el('pv-dark-btn');
        if (pc) pc.classList.toggle('pv-dark', _darkOn);
        if (btn) {
            btn.textContent = _darkOn ? '☀ Light' : '◑ Dark';
            btn.style.background = _darkOn ? 'rgba(100,160,255,.2)' : '';
            btn.style.color = _darkOn ? '#7ab8ff' : '';
            btn.style.borderColor = _darkOn ? '#5090ff' : 'rgba(100,160,255,.3)';
        }
        try { localStorage.setItem(PV_DARK_KEY, _darkOn ? '1' : '0'); } catch (e) {}
    }

    function toggleDark() {
        setDark(!_darkOn);
    }

    function initTheme() {
        try { setDark(localStorage.getItem(PV_DARK_KEY) === '1'); } catch (e) {}
    }

    /* 렌더 후 scale 유지. 첫 렌더 시에는 창에 맞게 자동 fit */
    let _firstRender = true;
    function refresh() {
        const pc = el('preview-container');
        if (_firstRender) {
            _firstRender = false;
            if (pc.classList.contains('slide-mode')) {
                pc.style.fontSize = Math.round(_pvFontPt * (96 / 72)) + 'px';
                _updateFontLbl();
            } else {
                requestAnimationFrame(() => fitToPane());
            }
            return;
        }
        if (pptOn) {
            /* PPT 모드 중 재렌더: 스타일 재적용 */
            setTimeout(() => {
                const pane = el('preview-pane');
                const vw = pane.clientWidth;
                const MM = 96 / 25.4;
                const origPx = Math.round(210 * MM);
                const ratio = vw / origPx;
                const fontPx = Math.round(_pvFontPt * (96 / 72) * ratio);
                const sel = pc.classList.contains('slide-mode') ? '.ppt-slide' : '.preview-page';
                pc.querySelectorAll(sel).forEach(p => {
                    p.style.width = vw + 'px';
                    p.style.padding = Math.round(22 * MM * ratio) + 'px ' + Math.round(18 * MM * ratio) + 'px';
                    p.style.minHeight = Math.round(297 * MM * ratio) + 'px';
                    p.style.marginBottom = '0';
                    p.style.boxSizing = 'border-box';
                    p.style.fontSize = fontPx + 'px';
                    p.style.lineHeight = '1.8';
                });
                const pages = getPages();
                el('ppt-pg').textContent = pages.length ? `${pptIdx + 1} / ${pages.length}` : '0 / 0';
            }, 50);
            return;
        }
        if (pc.classList.contains('slide-mode')) {
            pc.style.fontSize = Math.round(_pvFontPt * (96 / 72)) + 'px';
            _updateFontLbl();
        }
        if (scale !== 1.0) setScale(scale);
    }

    return { zoomIn, zoomOut, fitToPane, fontUp, fontDown, togglePPT, pptPrev, pptNext, refresh, toggleDark, setDark, initTheme, toggleTrans };
})();