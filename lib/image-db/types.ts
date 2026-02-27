/**
 * Shared types for IndexedDB image handling (MDPro-style).
 */

export interface InsertImageOptions {
  width?: number;
  height?: number;
}

export interface ParsedIndexedDBSrc {
  uuid: string;
  width?: number;
  height?: number;
}
