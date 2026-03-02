/* ═══════════════════════════════════════════════════════════
   에디터 인라인 명령 (취소선, 밑줄, 목록, 링크 등)
   의존: el (dom.js), US, TM, App (전역)
   index.js ACTION_MAP에서 참조: EdCommands.xxx()
═══════════════════════════════════════════════════════════ */
const EdCommands = {
    strikethrough() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        const sel = ed.value.slice(s, e2) || '텍스트';
        ed.setRangeText(`~~${sel}~~`, s, e2, 'end');
        US.snap(); TM.markDirty();
    },
    underline() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        const sel = ed.value.slice(s, e2) || '텍스트';
        ed.setRangeText(`<u>${sel}</u>`, s, e2, 'end');
        US.snap(); TM.markDirty();
    },
    sup() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(`<sup>${ed.value.slice(s, e2) || '텍스트'}</sup>`, s, e2, 'end');
        US.snap(); TM.markDirty();
    },
    sub() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(`<sub>${ed.value.slice(s, e2) || '텍스트'}</sub>`, s, e2, 'end');
        US.snap(); TM.markDirty();
    },
    highlight() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        ed.setRangeText(`==${ed.value.slice(s, e2) || '텍스트'}==`, s, e2, 'end');
        US.snap(); TM.markDirty();
    },
    hr() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        ed.setRangeText('\n---\n', p, p, 'end');
        US.snap(); TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    ul() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        const s = ed.value.lastIndexOf('\n', p - 1) + 1;
        ed.setRangeText('- ', s, s, 'start');
        US.snap(); TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    ol() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        const s = ed.value.lastIndexOf('\n', p - 1) + 1;
        ed.setRangeText('1. ', s, s, 'start');
        US.snap(); TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    task() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        const s = ed.value.lastIndexOf('\n', p - 1) + 1;
        ed.setRangeText('- [ ] ', s, s, 'start');
        US.snap(); TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    link() {
        const ed = el('editor');
        if (!ed) return;
        const s = ed.selectionStart, e2 = ed.selectionEnd;
        const sel = ed.value.slice(s, e2) || '링크텍스트';
        ed.setRangeText(`[${sel}](url)`, s, e2, 'end');
        US.snap(); TM.markDirty();
    },
    image() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        ed.setRangeText('![설명](이미지URL)', p, p, 'end');
        US.snap(); TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    indentIn() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        const s = ed.value.lastIndexOf('\n', p - 1) + 1;
        ed.setRangeText('  ', s, s, 'start');
        US.snap(); TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    },
    indentOut() {
        const ed = el('editor');
        if (!ed) return;
        const p = ed.selectionStart;
        const s = ed.value.lastIndexOf('\n', p - 1) + 1;
        if (ed.value.slice(s, s + 2) === '  ') {
            ed.setRangeText('', s, s + 2, 'start');
            US.snap(); TM.markDirty();
            if (typeof App !== 'undefined' && App.render) App.render();
        }
    }
};
