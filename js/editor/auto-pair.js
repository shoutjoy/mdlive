/* EditorAutoPair — ( ) [ ] " " ' ' 자동쌍 & 선택 시 감싸기 */
const EditorAutoPair = (() => {
    const STORAGE_KEY = 'mdpro_editor_auto_pair';
    const PAIRS = { '(': ')', '[': ']', '"': '"', "'": "'", '{': '}', '<': '>' };

    function isEnabled() {
        try { return localStorage.getItem(STORAGE_KEY) !== 'off'; } catch (e) { return true; }
    }

    function updateUI() {
        const enabled = isEnabled();
        const btn = document.getElementById('hk-auto-pair-btn');
        if (btn) btn.textContent = enabled ? 'ON' : 'OFF';
    }

    function toggle() {
        let enabled = isEnabled();
        enabled = !enabled;
        try { localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off'); } catch (e) {}
        updateUI();
    }

    /** 에디터에서 ( [ " ' 입력 시 처리. 처리했으면 true, 아니면 false */
    function handleKey(e) {
        if (!e.key || e.key.length !== 1) return false;
        const open = e.key;
        const close = PAIRS[open];
        if (close === undefined) return false;
        if (e.ctrlKey || e.metaKey || e.altKey) return false;
        if (!isEnabled()) return false;

        const edi = document.getElementById('editor');
        if (!edi || document.activeElement !== edi) return false;

        const ss = edi.selectionStart;
        const se = edi.selectionEnd;
        const val = edi.value;

        if (ss !== se) {
            /* 선택 영역 wrap: "텍스트" → "텍스트" */
            e.preventDefault();
            const sel = val.substring(ss, se);
            edi.value = val.substring(0, ss) + open + sel + close + val.substring(se);
            edi.setSelectionRange(ss + 1 + sel.length, ss + 1 + sel.length);
            edi.focus();
            if (typeof US !== 'undefined') US.snap();
            if (typeof TM !== 'undefined') TM.markDirty();
            if (typeof App !== 'undefined' && App.render) App.render();
            return true;
        }

        /* 커서만 있을 때: 자동쌍 ( ) [ ] " " ' ' */
        e.preventDefault();
        edi.value = val.substring(0, ss) + open + close + val.substring(se);
        edi.setSelectionRange(ss + 1, ss + 1);
        edi.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
        return true;
    }

    function init() {
        updateUI();
    }

    return { handleKey, isEnabled, toggle, init, updateUI };
})();
