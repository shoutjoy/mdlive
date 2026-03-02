/* CiteAiSearchHistory — AI 검색 결과 히스토리 (cite-modal, Deep Research) */
const CiteAiSearchHistory = (() => {
    const STORAGE_KEY = 'mdpro_cite_ai_search_history';
    const LIST_EL_ID = 'cite-ai-history-list';

    function getList() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch (e) { return []; }
    }
    function setList(arr) {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(arr)); } catch (e) {}
    }
    function saveCurrent() {
        const out = document.getElementById('dr-output');
        const q = document.getElementById('dr-ai-prompt');
        if (!out) return;
        const result = (out.value || '').trim();
        if (!result) return;
        const title = (q && q.value) ? q.value.trim().slice(0, 50) : ('AI검색 ' + new Date().toLocaleString('ko-KR'));
        const list = getList();
        const item = { id: 'aih-' + Date.now(), title, result, createdAt: Date.now() };
        list.unshift(item);
        setList(list.slice(0, 100));
        renderList();
    }
    function saveCurrentFromCiteModal() {
        const out = document.getElementById('cite-ai-out');
        const q = document.getElementById('cite-ai-prompt');
        if (!out) return;
        const result = (out.value || '').trim();
        if (!result) return;
        const title = (q && q.value) ? q.value.trim().slice(0, 50) : ('AI검색 ' + new Date().toLocaleString('ko-KR'));
        const list = getList();
        const item = { id: 'aih-' + Date.now(), title, result, createdAt: Date.now() };
        list.unshift(item);
        setList(list.slice(0, 100));
        renderList();
    }
    function loadItem(id) {
        const list = getList();
        const item = list.find(x => x.id === id);
        if (!item) return;
        const citeModal = document.getElementById('cite-modal');
        const cpAiSearch = document.getElementById('cp-ai-search');
        const isCiteAiSearchActive = citeModal && citeModal.classList.contains('vis') && cpAiSearch && cpAiSearch.classList.contains('active');
        if (isCiteAiSearchActive) {
            const out = document.getElementById('cite-ai-out');
            if (out) out.value = item.result;
            return;
        }
        if (typeof DeepResearch !== 'undefined') {
            DeepResearch.show();
            DeepResearch.switchTab('ai-search');
            const out = document.getElementById('dr-output');
            if (out) out.value = item.result;
        }
    }
    function deleteItem(id) {
        setList(getList().filter(x => x.id !== id));
        renderList();
    }
    function clearAll() {
        setList([]);
        renderList();
    }
    function renderList() {
        const el = document.getElementById(LIST_EL_ID);
        if (!el) return;
        const list = getList();
        if (!list.length) {
            el.innerHTML = '<div class="cite-empty" style="font-size:11px;color:var(--tx3);padding:12px">' + (el.getAttribute('data-empty') || '저장된 항목이 없습니다.') + '</div>';
            return;
        }
        el.innerHTML = list.map(item => {
            const d = new Date(item.createdAt);
            const dateStr = d.toLocaleDateString('ko-KR') + ' ' + d.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' });
            const titleEsc = (item.title || '제목 없음').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return '<div class="ref-card" style="margin-bottom:6px;padding:6px 8px;"><div style="font-size:11px;color:var(--tx);margin-bottom:4px">' + titleEsc + '</div><div style="font-size:10px;color:var(--tx3);margin-bottom:4px">' + dateStr + '</div><div style="display:flex;gap:4px"><button type="button" class="btn btn-p btn-sm" style="font-size:10px" onclick="CiteAiSearchHistory.loadItem(\'' + item.id + '\')">불러오기</button><button type="button" class="btn btn-g btn-sm" style="font-size:10px" onclick="CiteAiSearchHistory.deleteItem(\'' + item.id + '\')">삭제</button></div></div>';
        }).join('');
    }
    return { getList, saveCurrent, saveCurrentFromCiteModal, loadItem, deleteItem, clearAll, renderList };
})();
