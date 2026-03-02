/* AuthorInfo — 이름/소속/메일/연락처 저장 및 Shift+Alt+A 삽입 → js/ui/author-info.js
   의존: US, TM, App(전역) */

/* ═══════════════════════════════════════════════════════════
   AUTHOR INFO — 이름/소속/메일/연락처 저장 및 Shift+Alt+A 삽입
═══════════════════════════════════════════════════════════ */
const AuthorInfo = (() => {
    const STORAGE_KEY = 'mdpro_author_info';
    const INSERT_KEY = 'mdpro_author_insert';
    const DEFAULT_INSERT = { name: true, affiliation: false, email: false, contact: false };

    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : { name: '', affiliation: '', email: '', contact: '' };
        } catch (e) { return { name: '', affiliation: '', email: '', contact: '' }; }
    }

    function loadInsert() {
        try {
            const raw = localStorage.getItem(INSERT_KEY);
            return raw ? JSON.parse(raw) : { ...DEFAULT_INSERT };
        } catch (e) { return { ...DEFAULT_INSERT }; }
    }

    function saveInputs() {
        const name = document.getElementById('hk-author-name');
        const affiliation = document.getElementById('hk-author-affiliation');
        const email = document.getElementById('hk-author-email');
        const contact = document.getElementById('hk-author-contact');
        if (!name) return;
        const data = {
            name: (name.value || '').trim(),
            affiliation: (affiliation && affiliation.value ? affiliation.value : '').trim(),
            email: (email && email.value ? email.value : '').trim(),
            contact: (contact && contact.value ? contact.value : '').trim()
        };
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch (e) {}
        saveInsertFromCheckboxes();
    }

    function saveInsertFromCheckboxes() {
        const chkName = document.getElementById('hk-insert-name');
        const chkAff = document.getElementById('hk-insert-affiliation');
        const chkEmail = document.getElementById('hk-insert-email');
        const chkContact = document.getElementById('hk-insert-contact');
        if (!chkName) return;
        const data = {
            name: !!chkName.checked,
            affiliation: !!(chkAff && chkAff.checked),
            email: !!(chkEmail && chkEmail.checked),
            contact: !!(chkContact && chkContact.checked)
        };
        try { localStorage.setItem(INSERT_KEY, JSON.stringify(data)); } catch (e) {}
    }

    function loadToPanel() {
        const data = load();
        const nameEl = document.getElementById('hk-author-name');
        const affEl = document.getElementById('hk-author-affiliation');
        const emailEl = document.getElementById('hk-author-email');
        const contactEl = document.getElementById('hk-author-contact');
        if (nameEl) nameEl.value = data.name || '';
        if (affEl) affEl.value = data.affiliation || '';
        if (emailEl) emailEl.value = data.email || '';
        if (contactEl) contactEl.value = data.contact || '';

        const ins = loadInsert();
        const chkName = document.getElementById('hk-insert-name');
        const chkAff = document.getElementById('hk-insert-affiliation');
        const chkEmail = document.getElementById('hk-insert-email');
        const chkContact = document.getElementById('hk-insert-contact');
        if (chkName) chkName.checked = ins.name;
        if (chkAff) chkAff.checked = ins.affiliation;
        if (chkEmail) chkEmail.checked = ins.email;
        if (chkContact) chkContact.checked = ins.contact;

        [chkName, chkAff, chkEmail, chkContact].forEach(elm => {
            if (elm) elm.removeEventListener('change', saveInsertFromCheckboxes);
            if (elm) elm.addEventListener('change', saveInsertFromCheckboxes);
        });
    }

    function getTextToInsert() {
        const data = load();
        const ins = loadInsert();
        const lines = [];
        if (ins.name && data.name) lines.push(data.name);
        if (ins.affiliation && data.affiliation) lines.push(data.affiliation);
        if (ins.email && data.email) lines.push(data.email);
        if (ins.contact && data.contact) lines.push(data.contact);
        return lines.join('\n');
    }

    function getAllWrittenText() {
        const nameEl = document.getElementById('hk-author-name');
        const affEl = document.getElementById('hk-author-affiliation');
        const emailEl = document.getElementById('hk-author-email');
        const contactEl = document.getElementById('hk-author-contact');
        const lines = [];
        if (nameEl && (nameEl.value || '').trim()) lines.push((nameEl.value || '').trim());
        if (affEl && (affEl.value || '').trim()) lines.push((affEl.value || '').trim());
        if (emailEl && (emailEl.value || '').trim()) lines.push((emailEl.value || '').trim());
        if (contactEl && (contactEl.value || '').trim()) lines.push((contactEl.value || '').trim());
        return lines.join('\n');
    }

    function insertIntoEditor() {
        const ed = document.getElementById('editor');
        if (!ed) return;
        const text = getTextToInsert();
        if (!text) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const val = ed.value;
        ed.value = val.substring(0, s) + text + val.substring(e);
        ed.setSelectionRange(s + text.length, s + text.length);
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    function insertAllIntoEditor() {
        const ed = document.getElementById('editor');
        if (!ed) return;
        const text = getAllWrittenText();
        if (!text) return;
        const s = ed.selectionStart, e = ed.selectionEnd;
        const val = ed.value;
        ed.value = val.substring(0, s) + text + val.substring(e);
        ed.setSelectionRange(s + text.length, s + text.length);
        ed.focus();
        if (typeof US !== 'undefined') US.snap();
        if (typeof TM !== 'undefined') TM.markDirty();
        if (typeof App !== 'undefined' && App.render) App.render();
    }

    return { load, loadInsert, saveInputs, loadToPanel, getTextToInsert, getAllWrittenText, insertIntoEditor, insertAllIntoEditor };
})();
