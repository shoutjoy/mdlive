/* CAP — Caption Manager (표/그림 캡션 삽입) */
const CAP = (() => {
    let type = 'table'; let selOpt = 0;

    const tableOpts = [
        { label: '&lt;표 N&gt;', template: (n, d) => `<표${n}> ${d}` },
        { label: '표 N.', template: (n, d) => `표 ${n}. ${d}` },
        { label: '&lt;Table N&gt;', template: (n, d) => `<Table ${n}> ${d}` },
        { label: 'Table N.', template: (n, d) => `Table ${n}. ${d}` },
    ];
    const figOpts = [
        { label: '[그림 N]', template: (n, d) => `[그림 ${n}] ${d}` },
        { label: '그림 N.', template: (n, d) => `그림 ${n}. ${d}` },
        { label: '[Fig N]', template: (n, d) => `[Fig ${n}] ${d}` },
        { label: 'Fig N.', template: (n, d) => `Fig ${n}. ${d}` },
        { label: '[Figure N]', template: (n, d) => `[Figure ${n}] ${d}` },
        { label: 'Figure N.', template: (n, d) => `Figure ${n}. ${d}` },
    ];

    function show(t) {
        type = t; selOpt = 0;
        el('cap-title').textContent = t === 'table' ? '표 캡션 삽입' : '그림 캡션 삽입';
        const opts = t === 'table' ? tableOpts : figOpts;
        el('cap-opts').innerHTML = opts.map((o, i) => `<span class="cap-opt${i === 0 ? ' sel' : ''}" onclick="CAP.selOpt(${i})">${o.label}</span>`).join('');
        el('cap-num').value = '1'; el('cap-desc').value = '';
        updatePreview();
        el('caption-modal').classList.add('vis');
    }

    function selOptFn(i) {
        selOpt = i;
        document.querySelectorAll('#cap-opts .cap-opt').forEach((o, j) => o.classList.toggle('sel', j === i));
        updatePreview();
    }

    function updatePreview() {
        const opts = type === 'table' ? tableOpts : figOpts;
        const n = el('cap-num').value || '1';
        const d = el('cap-desc').value || '(캡션 내용)';
        el('cap-preview').textContent = opts[selOpt].template(n, d);
    }

    function insert() {
        const opts = type === 'table' ? tableOpts : figOpts;
        const n = el('cap-num').value || '1';
        const d = el('cap-desc').value || '내용';
        const caption = opts[selOpt].template(n, d);
        const ed = el('editor'); const pos = ed.selectionEnd;
        const cssClass = type === 'table' ? 'tbl-caption' : 'fig-caption';
        const md = `\n<span class="${cssClass}">${caption}</span>\n`;
        ins(ed, pos, pos, md);
        App.hideModal('caption-modal');
    }

    return { show, selOpt: selOptFn, updatePreview, insert };
})();
