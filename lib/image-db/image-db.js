/**
 * IndexedDB image handling — production-ready JS bundle (no build step).
 * API: ImageDB.insertImage(blob, alt, { width?, height? }), ImageDB.resolveIndexedDBImages(container), ImageDB.revokeIndexedDBUrls(container).
 */
(function (global) {
  'use strict';

  const DB_NAME = 'mdlive-image-db';
  const STORE_NAME = 'images';
  const DB_VERSION = 1;
  const PREFIX = 'indexeddb://';

  function open() {
    return new Promise(function (resolve, reject) {
      var request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onerror = function () { reject(request.error); };
      request.onsuccess = function () { resolve(request.result); };
      request.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
      };
    });
  }

  function set(id, blob) {
    return open().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE_NAME, 'readwrite');
        tx.objectStore(STORE_NAME).put({ id: id, blob: blob });
        tx.oncomplete = function () { db.close(); resolve(); };
        tx.onerror = function () { db.close(); reject(tx.error); };
      });
    });
  }

  function get(id) {
    return open().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE_NAME, 'readonly');
        var req = tx.objectStore(STORE_NAME).get(id);
        req.onsuccess = function () {
          db.close();
          var row = req.result;
          resolve(row && row.blob != null ? row.blob : null);
        };
        req.onerror = function () { db.close(); reject(req.error); };
      });
    });
  }

  function generateUUID() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      var v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  function buildIndexedDBUrl(uuid, options) {
    var url = 'indexeddb://' + uuid;
    var params = [];
    if (options && options.width != null && Number.isFinite(options.width)) {
      params.push('width=' + encodeURIComponent(Math.round(options.width)));
    }
    if (options && options.height != null && Number.isFinite(options.height)) {
      params.push('height=' + encodeURIComponent(Math.round(options.height)));
    }
    return params.length ? url + '?' + params.join('&') : url;
  }

  function insertImage(blob, alt, options) {
    if (!blob || !(blob instanceof Blob)) {
      return Promise.reject(new Error('insertImage: blob is required'));
    }
    var uuid = generateUUID();
    return set(uuid, blob).then(function () {
      var url = buildIndexedDBUrl(uuid, options);
      var escapedAlt = (alt || '').replace(/\]/g, '\\]');
      return '![' + escapedAlt + '](' + url + ')';
    });
  }

  var containerUrls = new WeakMap();

  function parseIndexedDBSrc(src) {
    if (!src || src.indexOf(PREFIX) !== 0) return null;
    try {
      var rest = src.slice(PREFIX.length);
      var idx = rest.indexOf('?');
      var idPart = idx >= 0 ? rest.slice(0, idx) : rest;
      var qs = idx >= 0 ? rest.slice(idx + 1) : '';
      var uuid = idPart.trim();
      if (!uuid) return null;
      var out = { uuid: uuid };
      if (qs) {
        var parts = qs.split('&');
        for (var i = 0; i < parts.length; i++) {
          var p = parts[i].split('=');
          var key = decodeURIComponent(p[0]).toLowerCase();
          var val = p[1] != null ? parseInt(decodeURIComponent(p[1]), 10) : NaN;
          if (key === 'width' && Number.isFinite(val) && val > 0) out.width = val;
          if (key === 'height' && Number.isFinite(val) && val > 0) out.height = val;
        }
      }
      return out;
    } catch (e) {
      return null;
    }
  }

  function applyDimensions(img, width, height) {
    if (width != null && height != null) {
      img.style.width = width + 'px';
      img.style.height = height + 'px';
      img.style.objectFit = 'contain';
    } else if (width != null) {
      img.style.width = width + 'px';
      img.style.height = 'auto';
      img.style.maxWidth = '100%';
    } else if (height != null) {
      img.style.height = height + 'px';
      img.style.width = 'auto';
      img.style.maxHeight = '100%';
    }
    img.style.display = 'inline-block';
  }

  function revokeUrlsForContainer(container) {
    var urlSet = containerUrls.get(container);
    if (urlSet) {
      urlSet.forEach(function (url) {
        try { URL.revokeObjectURL(url); } catch (e) {}
      });
      urlSet.clear();
      containerUrls.delete(container);
    }
  }

  function getDimensionsFromImg(img) {
    var dw = img.getAttribute('data-width');
    var dh = img.getAttribute('data-height');
    var w = dw != null ? parseInt(dw, 10) : NaN;
    var h = dh != null ? parseInt(dh, 10) : NaN;
    var out = {};
    if (Number.isFinite(w) && w > 0) out.width = w;
    if (Number.isFinite(h) && h > 0) out.height = h;
    return out;
  }

  function resolveOne(img, urlSet) {
    var src = img.getAttribute('src') || img.src;
    var parsed = parseIndexedDBSrc(src);
    if (!parsed) return Promise.resolve();

    return get(parsed.uuid).then(function (blob) {
      if (!blob) {
        img.alt = img.alt || '(Image not found)';
        img.style.color = 'var(--tx3, #888)';
        return;
      }
      var blobUrl = URL.createObjectURL(blob);
      urlSet.add(blobUrl);
      var dims = getDimensionsFromImg(img);
      var width = parsed.width != null ? parsed.width : dims.width;
      var height = parsed.height != null ? parsed.height : dims.height;
      img.src = blobUrl;
      applyDimensions(img, width, height);
      img.addEventListener('load', function () {
        applyDimensions(img, width, height);
      }, { once: true });
      img.addEventListener('error', function () {
        img.alt = img.alt || '(Image load error)';
        try { URL.revokeObjectURL(blobUrl); urlSet.delete(blobUrl); } catch (e) {}
      }, { once: true });
    }).catch(function () {
      img.alt = img.alt || '(Image load failed)';
      img.style.color = 'var(--tx3, #888)';
    });
  }

  function resolveIndexedDBImages(container) {
    if (!container || !container.querySelectorAll) return Promise.resolve();
    revokeUrlsForContainer(container);
    var urlSet = new Set();
    containerUrls.set(container, urlSet);
    var imgs = container.querySelectorAll('img[src^="' + PREFIX + '"]');
    var promises = [];
    for (var i = 0; i < imgs.length; i++) {
      promises.push(resolveOne(imgs[i], urlSet));
    }
    return Promise.all(promises);
  }

  function revokeIndexedDBUrls(container) {
    revokeUrlsForContainer(container);
  }

  global.ImageDB = {
    insertImage: insertImage,
    resolveIndexedDBImages: resolveIndexedDBImages,
    revokeIndexedDBUrls: revokeIndexedDBUrls,
    open: open,
    get: get,
    set: set
  };
})(typeof window !== 'undefined' ? window : this);
