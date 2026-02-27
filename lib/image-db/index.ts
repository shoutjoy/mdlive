/**
 * Public API for IndexedDB-based image handling (MDPro-style).
 *
 * - insertImage(blob, alt, { width?, height? }) → Markdown string
 * - resolveIndexedDBImages(container) → replace indexeddb:// in DOM, cleanup on re-render
 * - revokeIndexedDBUrls(container) → manual cleanup
 */

export { insertImage } from './insert';
export { resolveIndexedDBImages, revokeIndexedDBUrls } from './resolve';
export { get, set, open } from './store';
export type { InsertImageOptions, ParsedIndexedDBSrc } from './types';
