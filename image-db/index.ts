/**
 * Image IndexedDB — public API.
 * Store images as Blobs in IndexedDB, insert as markdown with optional dimensions,
 * resolve indexeddb:// in rendered HTML with proper cleanup.
 */

export { open, get, set } from './store';
export { insertImage } from './insert';
export { resolveIndexedDBImages, revokeUrlsForContainer } from './resolve';
export { preprocessMarkdownForIndexedDBImages } from './preprocess';
export type { InsertImageOptions, ResolvedDimensions } from './types';
export { INDEXEDDB_IMAGE_SCHEME, DB_NAME, STORE_NAME, DB_VERSION } from './types';
