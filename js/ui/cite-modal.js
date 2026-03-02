/* CiteModal — 참고문헌 모달 최대화 (앱 내 전체화면) */
const CiteModal = {
    toggleMaximize() {
        const box = document.getElementById('cite-modal-box');
        const btn = document.getElementById('cite-modal-maximize-btn');
        if (!box) return;
        const on = box.classList.toggle('cite-modal-maximized');
        if (btn) { btn.title = on ? '원래 크기' : '최대화'; btn.textContent = on ? '⤢' : '⛶'; }
    }
};
