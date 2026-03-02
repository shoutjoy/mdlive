/* ImgStore — 이미지 IDB 저장 */
const ImgStore = (() => {
    const DB = 'mdlive-img-store';
    const STORE = 'images';
    function open() {
        return new Promise((res, rej) => {
            const r = indexedDB.open(DB, 1);
            r.onupgradeneeded = e => {
                if (!e.target.result.objectStoreNames.contains(STORE)) e.target.result.createObjectStore(STORE, { keyPath: 'id' });
            };
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
        });
    }
    async function save(dataUrl, alt) {
        if (!dataUrl || !dataUrl.startsWith('data:image')) return;
        try {
            const db = await open();
            await new Promise((res, rej) => {
                const t = db.transaction(STORE, 'readwrite');
                t.objectStore(STORE).put({ id: 'img-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9), dataUrl, alt: alt || '', createdAt: Date.now() });
                t.oncomplete = () => res();
                t.onerror = () => rej(t.error);
            });
        } catch (e) {
        }
    }
    return { save };
})();
