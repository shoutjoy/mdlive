/**
 * Image IndexedDB module — shared types.
 */

export interface InsertImageOptions {
  width?: number;
  height?: number;
}

export interface ResolvedDimensions {
  width?: number;
  height?: number;
}

export const INDEXEDDB_IMAGE_SCHEME = 'indexeddb://' as const;
export const DB_NAME = 'mdlive-image-db';
export const STORE_NAME = 'images';
export const DB_VERSION = 1;
