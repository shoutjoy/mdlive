/* ═══════════════════════════════════════════════════════════
   CORE RENDER — App.render() 내부 플러시 로직
   호출: App.render()에서 setTimeout 콜백으로 Render.run(md, title) 호출
   의존: el, formatDateTime, PR, TOC, LN, TM, AS, PW, detectErrors, App (전역)
═══════════════════════════════════════════════════════════ */
const Render = {
    /**
     * 미리보기·통계·목차·자동저장 등 한 번에 플러시 (기존 App.render 내부 setTimeout 콜백과 동일)
     */
    run(md, title) {
        if (typeof PR !== 'undefined' && PR.render) PR.render(md);
        if (typeof PvImageResize !== 'undefined' && PvImageResize.init) PvImageResize.init(md);
        if (typeof TOC !== 'undefined' && TOC.build) TOC.build(md);
        const errs = typeof detectErrors === 'function' ? detectErrors(md) : [];
        if (typeof App !== 'undefined' && App.showErrs) App.showErrs(errs);
        const words = md.trim() ? md.trim().split(/\s+/).length : 0;
        const swEl = el('sw');
        if (swEl) swEl.textContent = words.toLocaleString() + ' 단어';
        const scEl = el('sc');
        if (scEl) scEl.textContent = md.length.toLocaleString() + ' 자';
        const spEl = el('sp');
        if (spEl) spEl.textContent = '약 ' + Math.ceil(words / 250) + ' 페이지';
        if (typeof LN !== 'undefined' && LN.update) LN.update();
        const dtEl = el('app-datetime');
        if (dtEl) dtEl.textContent = typeof formatDateTime === 'function' ? formatDateTime() : '';
        if (typeof TM !== 'undefined' && TM.syncTitle) TM.syncTitle(title);
        if (typeof AS !== 'undefined' && AS.save) AS.save(md, title);
        if (typeof PW !== 'undefined' && PW.sync) PW.sync();
        if (typeof PVShare !== 'undefined' && PVShare.refresh) PVShare.refresh();
        const findBar = el('find-bar');
        const fiEl = el('fi');
        if (findBar && findBar.classList.contains('vis') && fiEl && fiEl.value.trim() && typeof App !== 'undefined' && App.updateFindHighlight) {
            App.updateFindHighlight();
        }
    }
};
