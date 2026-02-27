/**
 * Resolve indexeddb:// images in the DOM: load Blob from IndexedDB,
 * replace src with blob URL, apply width/height with aspect-ratio safety.
 * Tracks blob URLs per container and revokes them on re-render to avoid leaks.
 */

import { get } from './store';
import { INDEXEDDB_IMAGE_SCHEME, ResolvedDimensions } from './types';

const SCHEME_LENGTH = INDEXEDDB_IMAGE_SCHEME.length;

/** Per-container set of blob URLs we created, for safe revoke on re-render */
const containerUrls = new WeakMap<HTMLElement, Set<string>>();

function getOrCreateUrlSet(container: HTMLElement): Set<string> {
  let set = containerUrls.get(container);
  if (!set) {
    set = new Set<string>();
    containerUrls.set(container, set);
  }
  return set;
}

/**
 * Parse src: "indexeddb://uuid" or "indexeddb://uuid?width=300&height=200".
 * Returns { uuid, width?, height? }.
 */
function parseIndexedDBSrc(src: string): { uuid: string; width?: number; height?: number } | null {
  if (!src.startsWith(INDEXEDDB_IMAGE_SCHEME)) return null;
  const rest = src.slice(SCHEME_LENGTH);
  const [uuidPart, queryPart] = rest.split('?');
  const uuid = uuidPart?.trim();
  if (!uuid) return null;
  const result: { uuid: string; width?: number; height?: number } = { uuid };
  if (queryPart) {
    const params = new URLSearchParams(queryPart);
    const w = params.get('width');
    const h = params.get('height');
    if (w != null && w !== '') {
      const n = parseInt(w, 10);
      if (!Number.isNaN(n) && n > 0) result.width = n;
    }
    if (h != null && h !== '') {
      const n = parseInt(h, 10);
      if (!Number.isNaN(n) && n > 0) result.height = n;
    }
  }
  return result;
}

/**
 * Get dimensions from img: data-width/data-height, or parsed from src query.
 */
function getDimensionsFromImg(img: HTMLImageElement, parsed: { width?: number; height?: number }): ResolvedDimensions {
  const dataW = img.getAttribute('data-width');
  const dataH = img.getAttribute('data-height');
  let width: number | undefined;
  let height: number | undefined;
  if (dataW != null && dataW !== '') {
    const n = parseInt(dataW, 10);
    if (!Number.isNaN(n) && n > 0) width = n;
  }
  if (dataH != null && dataH !== '') {
    const n = parseInt(dataH, 10);
    if (!Number.isNaN(n) && n > 0) height = n;
  }
  if (width == null) width = parsed.width;
  if (height == null) height = parsed.height;
  return { width, height };
}

/**
 * Apply width/height to img via inline style. Maintains aspect ratio when only one dimension is set; no distortion.
 */
function applyDimensions(img: HTMLImageElement, dims: ResolvedDimensions): void {
  const { width, height } = dims;
  if (width != null && height != null) {
    img.style.width = `${width}px`;
    img.style.height = `${height}px`;
    img.style.objectFit = 'contain';
  } else if (width != null) {
    img.style.width = `${width}px`;
    img.style.height = 'auto';
    img.style.maxWidth = '100%';
  } else if (height != null) {
    img.style.width = 'auto';
    img.style.height = `${height}px`;
    img.style.maxHeight = '100%';
  }
  img.style.display = '';
}

/**
 * Resolve a single img element: load from IndexedDB, set blob URL, apply dimensions.
 * Returns the blob URL if created (for tracking); revokes previous URL if img had one stored.
 */
async function resolveOneImg(
  img: HTMLImageElement,
  container: HTMLElement,
  urlSet: Set<string>
): Promise<void> {
  const src = img.getAttribute('src') ?? img.src;
  const parsed = parseIndexedDBSrc(src);
  if (!parsed) return;

  const prevUrl = (img as HTMLImageElement & { _indexedDbBlobUrl?: string })._indexedDbBlobUrl;
  if (prevUrl) {
    URL.revokeObjectURL(prevUrl);
    urlSet.delete(prevUrl);
    delete (img as HTMLImageElement & { _indexedDbBlobUrl?: string })._indexedDbBlobUrl;
  }

  const blob = await get(parsed.uuid);
  if (blob == null) {
    img.alt = img.alt || '[Image not found]';
    img.removeAttribute('src');
    return;
  }

  const blobUrl = URL.createObjectURL(blob);
  urlSet.add(blobUrl);
  (img as HTMLImageElement & { _indexedDbBlobUrl?: string })._indexedDbBlobUrl = blobUrl;

  const dims = getDimensionsFromImg(img, parsed);

  img.src = blobUrl;
  applyDimensions(img, dims);

  img.onload = (): void => {
    if (dims.width != null && dims.height == null) {
      img.style.height = 'auto';
    } else if (dims.height != null && dims.width == null) {
      img.style.width = 'auto';
    }
  };
}

/**
 * Revoke all blob URLs previously created for this container. Call before re-render or when container is discarded.
 */
export function revokeUrlsForContainer(container: HTMLElement): void {
  const set = containerUrls.get(container);
  if (!set) return;
  set.forEach((url) => {
    try {
      URL.revokeObjectURL(url);
    } catch {
      // ignore
    }
  });
  set.clear();
}

/**
 * Resolve all img[src^="indexeddb://"] in the container: load Blobs, replace src with blob URLs, apply dimensions.
 * Call after markdown is rendered to HTML. Safe to call multiple times; revokes previous blob URLs for this container first.
 */
export async function resolveIndexedDBImages(container: HTMLElement): Promise<void> {
  revokeUrlsForContainer(container);
  const urlSet = getOrCreateUrlSet(container);
  const imgs = Array.from(container.querySelectorAll<HTMLImageElement>('img[src^="indexeddb://"]'));
  await Promise.all(imgs.map((img) => resolveOneImg(img, container, urlSet)));
}
