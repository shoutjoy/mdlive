/**
 * IndexedDB helper for image Blob storage.
 * Open, get, set with UUID keys. Async-safe, defensive error handling.
 */

import { DB_NAME, STORE_NAME, DB_VERSION } from './types';

let dbInstance: IDBDatabase | null = null;

/**
 * Open the database (singleton). Creates object store on first run.
 */
export function open(): Promise<IDBDatabase> {
  if (dbInstance != null) return Promise.resolve(dbInstance);

  return new Promise<IDBDatabase>((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB is not available'));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB open failed'));
    request.onsuccess = () => {
      dbInstance = request.result;
      resolve(dbInstance);
    };
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

/**
 * Store a Blob by UUID. Overwrites if id exists.
 */
export function set(id: string, blob: Blob): Promise<void> {
  return open().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.put({ id, blob, updatedAt: Date.now() });
        request.onerror = () => reject(request.error ?? new Error('IndexedDB put failed'));
        request.onsuccess = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
      })
  );
}

/**
 * Get a Blob by UUID. Returns null if not found or on error.
 */
export function get(id: string): Promise<Blob | null> {
  return open()
    .then(
      (db) =>
        new Promise<{ blob: Blob } | undefined>((resolve, reject) => {
          const tx = db.transaction(STORE_NAME, 'readonly');
          const store = tx.objectStore(STORE_NAME);
          const request = store.get(id);
          request.onerror = () => reject(request.error ?? new Error('IndexedDB get failed'));
          request.onsuccess = () => resolve(request.result);
        })
    )
    .then((row) => (row?.blob != null ? row.blob : null))
    .catch(() => null);
}
