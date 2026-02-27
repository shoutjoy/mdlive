/**
 * IndexedDB helper for image Blob storage.
 * DB: single store, keyPath: id (UUID string), value: Blob.
 */

const DB_NAME = 'mdlive-image-db';
const STORE_NAME = 'images';
const DB_VERSION = 1;

export function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

export function set(id: string, blob: Blob): Promise<void> {
  return open().then((db) => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.put({ id, blob });
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  });
}

export function get(id: string): Promise<Blob | null> {
  return open().then((db) => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(id);
      request.onsuccess = () => {
        db.close();
        const row = request.result;
        resolve(row && row.blob != null ? row.blob : null);
      };
      request.onerror = () => { db.close(); reject(request.error); };
    });
  });
}
