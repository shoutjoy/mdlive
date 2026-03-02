/* DelConfirm — 파일 삭제 확인 모달 (로컬/GitHub 공용) */
const DelConfirm = (() => {
    let _cb = null;

    function show({ name, path, type, onConfirm }) {
        _cb = onConfirm;
        const modal  = document.getElementById('del-confirm-modal');
        const fname  = document.getElementById('dc-filename');
        const fpath  = document.getElementById('dc-filepath');
        const badge  = document.getElementById('dc-type-badge');
        const cmWrap = document.getElementById('dc-commit-wrap');
        const cmMsg  = document.getElementById('dc-commit-msg');
        if (!modal) return;

        if (fname)  fname.textContent  = name;
        if (fpath)  fpath.textContent  = path;
        if (badge) {
            badge.textContent  = type === 'github' ? '🐙 GitHub' : '💻 로컬';
            badge.style.background = type === 'github'
                ? 'rgba(124,106,247,.2)' : 'rgba(106,247,176,.15)';
            badge.style.borderColor = type === 'github'
                ? 'rgba(124,106,247,.5)' : 'rgba(106,247,176,.4)';
            badge.style.color = type === 'github' ? '#c0baff' : '#6af7b0';
        }
        if (cmWrap) cmWrap.style.display = type === 'github' ? '' : 'none';
        if (cmMsg)  cmMsg.value = `Delete ${name}`;

        modal.classList.add('vis');
        setTimeout(() => {
            const btn = document.getElementById('dc-confirm-btn');
            if (btn) btn.focus();
        }, 80);
    }

    function hide() {
        const modal = document.getElementById('del-confirm-modal');
        if (modal) modal.classList.remove('vis');
        _cb = null;
    }

    async function confirm() {
        if (typeof _cb !== 'function') { hide(); return; }
        const cmMsg = document.getElementById('dc-commit-msg');
        const msg   = cmMsg ? cmMsg.value.trim() : '';
        const cb = _cb;
        hide();
        try {
            await cb(msg);
        } catch(e) {
            alert('삭제 중 오류: ' + (e.message || e));
        }
    }

    return { show, hide, confirm };
})();
