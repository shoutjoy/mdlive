/**
 * Resolve indexeddb:// images in the DOM: load Blob from IndexedDB,
 * replace src with blob URL, apply width/height with aspect-ratio safety.
 * Tracks and revokes blob URLs on re-render to avoid memory leaks.
 */

import * as store from './store';
import type { ParsedIndexedDBSrc } from './types';

const PREFIX = 'indexeddb://';

/** Per-container set of blob URLs we created, for cleanup on re-render */
const containerUrls = new WeakMap<HTMLElement, Set<string>>();

function parseIndexedDBSrc(src: string): ParsedIndexedDBSrc | null {
  if (!src || !src.startsWith(PREFIX)) return null;
  try {
    const rest = src.slice(PREFIX.length);
    const [idPart, qs] = rest.includes('?') ? rest.split('?', 2) : [rest, ''];
    const uuid = idPart.trim();
    if (!uuid) return null;
    const out: ParsedIndexedDBSrc = { uuid };
    if (qs) {
      const params = new URLSearchParams(qs);
      const w = params.get('width');
      const h = params.get('height');
      if (w != null) {
        const n = parseInt(w, 10);
        if (Number.isFinite(n) && n > 0) out.width = n;
      }
      if (h != null) {
        const n = parseInt(h, 10);
        if (Number.isFinite(n) && n > 0) out.height = n;
      }
    }
    return out;
  } catch {
    return null;
  }
}

function getDimensionsFromImg(img: HTMLImageElement): { width?: number; height?: number } {
  const dw = img.getAttribute('data-width');
  const dh = img.getAttribute('data-height');
  const w = dw != null ? parseInt(dw, 10) : NaN;
  const h = dh != null ? parseInt(dh, 10) : NaN;
  const out: { width?: number; height?: number } = {};
  if (Number.isFinite(w) && w > 0) out.width = w;
  if (Number.isFinite(h) && h > 0) out.height = h;
  return out;
}

function applyDimensions(img: HTMLImageElement, width?: number, height?: number): void {
  if (width != null && height != null) {
    img.style.width = `${width}px`;
    img.style.height = `${height}px`;
    img.style.objectFit = 'contain';
  } else if (width != null) {
    img.style.width = `${width}px`;
    img.style.height = 'auto';
    img.style.maxWidth = '100%';
  } else if (height != null) {
    img.style.height = `${height}px`;
    img.style.width = 'auto';
    img.style.maxHeight = '100%';
  }
  img.style.display = 'inline-block';
}

function revokeUrlsForContainer(container: HTMLElement): void {
  const urls = containerUrls.get(container);
  if (urls) {
    urls.forEach((url) => {
      try {
        URL.revokeObjectURL(url);
      } catch {
        // ignore
      }
    });
    urls.clear();
    containerUrls.delete(container);
  }
}

async function resolveOne(img: HTMLImageElement, urlSet: Set<string>): Promise<void> {
  const src = img.getAttribute('src') || img.src;
  const parsed = parseIndexedDBSrc(src);
  if (!parsed) return;

  let blob: Blob | null = null;
  try {
    blob = await store.get(parsed.uuid);
  } catch {
    img.alt = img.alt || '(Image load failed)';
    img.style.color = 'var(--tx3, #888)';
    return;
  }

  if (!blob) {
    img.alt = img.alt || '(Image not found)';
    img.style.color = 'var(--tx3, #888)';
    return;
  }

  const blobUrl = URL.createObjectURL(blob);
  urlSet.add(blobUrl);

  const dims = getDimensionsFromImg(img);
  const width = parsed.width ?? dims.width;
  const height = parsed.height ?? dims.height;

  img.src = blobUrl;
  applyDimensions(img, width, height);

  img.addEventListener(
    'load',
    () => {
      applyDimensions(img, width, height);
    },
    { once: true }
  );
  img.addEventListener(
    'error',
    () => {
      img.alt = img.alt || '(Image load error)';
      try {
        URL.revokeObjectURL(blobUrl);
        urlSet.delete(blobUrl);
      } catch {
        // ignore
      }
    },
    { once: true }
  );
}

/**
 * Find all img elements in container whose src starts with indexeddb://,
 * load Blobs from IndexedDB, replace src with object URLs, apply dimensions.
 * Revokes any previous blob URLs for this container (safe re-render).
 */
export async function resolveIndexedDBImages(container: HTMLElement): Promise<void> {
  if (!container || !container.querySelectorAll) return;

  revokeUrlsForContainer(container);
  const urlSet = new Set<string>();
  containerUrls.set(container, urlSet);

  const imgs = container.querySelectorAll<HTMLImageElement>('img[src^="indexeddb://"]');
  const promises: Promise<void>[] = [];
  imgs.forEach((img) => promises.push(resolveOne(img, urlSet)));
  await Promise.all(promises);
}

/**
 * Revoke all blob URLs that were created for the given container.
 * Call when the container is removed from DOM or before re-rendering
 * if you do not call resolveIndexedDBImages again.
 */
export function revokeIndexedDBUrls(container: HTMLElement): void {
  revokeUrlsForContainer(container);
}
