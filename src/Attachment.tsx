import { useEffect, useRef, useState } from 'react';
import { AudioPlayer } from './AudioPlayer';
import { IconAttach } from './icons';
import { b64ToBytes } from './lib/bytes';
import {
  AttachmentMaterializationLimitError,
  MAX_MATERIALIZED_ATTACHMENT_BYTES,
  getAttachmentBlob,
  saveAttachmentToDisk,
  supportsStreamingAttachmentSave,
} from './lib/attachments';
import { isSticker } from './lib/stickers';
import { mayRenderInlineImage } from './lib/mediaPolicy';
import { sanitizeFilename } from './lib/filename';
import { t } from './lib/i18n';
import type { FileRef } from './lib/messages';

/** Resolve a message attachment to a Blob, from either storage format. Returns null
 *  if the referenced attachment is missing (e.g. arrived on this device by initial
 *  sync as a bare reference, or was garbage-collected). `attId` wins over inline. */
export async function resolveFileBlob(dek: CryptoKey, file: FileRef): Promise<Blob | null> {
  if (file.attId) return getAttachmentBlob(dek, file.attId);
  if (file.dataB64 !== undefined) {
    if (file.dataB64.length > Math.ceil((MAX_MATERIALIZED_ATTACHMENT_BYTES * 4) / 3) + 4) {
      throw new AttachmentMaterializationLimitError();
    }
    const bytes = b64ToBytes(file.dataB64);
    if (bytes.length > MAX_MATERIALIZED_ATTACHMENT_BYTES) {
      throw new AttachmentMaterializationLimitError();
    }
    return new Blob([bytes], { type: file.mime });
  }
  return null;
}

/** Full-screen image viewer. Takes a Blob and owns its object URL, so the URL's
 *  lifetime is the viewer's — not tied to a chat bubble that may scroll away. */
export function LightboxImg({ blob, onClose }: { blob: Blob; onClose: () => void }) {
  const [url, setUrl] = useState('');
  useEffect(() => {
    const u = URL.createObjectURL(blob);
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [blob]);
  return (
    <div className="lightbox" onClick={onClose} role="dialog" aria-label="Bild">
      {url && <img src={url} alt="" />}
      <button className="lightbox-close" onClick={onClose} aria-label="Schließen">
        ×
      </button>
    </div>
  );
}

export function downloadBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name || 'anhang';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/** Renders any message attachment: sticker, image, video, audio or a download chip.
 *  Loads the bytes from whichever store format the message uses and manages the
 *  object-URL lifecycle, so a 25 MB video is never a base64 data: URL in the DOM. */
export function Attachment({
  dek,
  file,
  onImageZoom,
  onStickerZoom,
}: {
  dek: CryptoKey;
  file: FileRef;
  onImageZoom: (blob: Blob) => void;
  onStickerZoom: (file: FileRef) => void;
}) {
  const [blob, setBlob] = useState<Blob | null>(null);
  const [state, setState] = useState<'idle' | 'loading' | 'ready' | 'large' | 'exporting' | 'missing'>('idle');
  const [exportError, setExportError] = useState('');

  // Lazy decrypt: a long or image-heavy chat (especially a group) used to decrypt
  // EVERY attachment the moment it opened — the main source of the lag. Only decrypt
  // once the attachment is near the viewport. Placeholder reserves space so scrolling
  // stays stable and the visible ones (bottom of the chat) load first.
  const anchorRef = useRef<HTMLDivElement>(null);
  const [near, setNear] = useState(false);
  useEffect(() => {
    if (near) return;
    const el = anchorRef.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) setNear(true);
      },
      { rootMargin: '800px' }, // start a bit before it scrolls into view
    );
    io.observe(el);
    return () => io.disconnect();
  }, [near]);

  useEffect(() => {
    if (!near) return;
    let alive = true;
    setState('loading');
    void (async () => {
      try {
        const b = await resolveFileBlob(dek, file);
        if (!alive) return;
        setBlob(b);
        setState(b ? 'ready' : 'missing');
      } catch (error) {
        if (!alive) return;
        setState(error instanceof AttachmentMaterializationLimitError ? 'large' : 'missing');
      }
    })();
    return () => {
      alive = false;
    };
  }, [near, dek, file]);

  // One object URL per resolved blob, revoked when it changes or unmounts.
  const [url, setUrl] = useState('');
  useEffect(() => {
    if (!blob) {
      setUrl('');
      return;
    }
    const u = URL.createObjectURL(blob);
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [blob]);

  if (state === 'missing') {
    return <div className="file-missing">{t('Anhang auf diesem Gerät nicht verfügbar')}</div>;
  }
  if (state === 'large' || state === 'exporting') {
    const canStream = !!file.attId && supportsStreamingAttachmentSave();
    return (
      <div ref={anchorRef}>
        <button
          className="file-chip"
          disabled={!canStream || state === 'exporting'}
          onClick={() => {
            if (!file.attId || !canStream) return;
            setExportError('');
            setState('exporting');
            void saveAttachmentToDisk(dek, file.attId, sanitizeFilename(file.name) || 'anhang')
              .catch((error: unknown) => {
                if (!(error instanceof DOMException && error.name === 'AbortError')) {
                  setExportError(error instanceof Error ? error.message : t('Export fehlgeschlagen.'));
                }
              })
              .finally(() => setState('large'));
          }}
        >
          <IconAttach size={15} />
          <span className="fn">
            {state === 'exporting' ? t('Anhang wird exportiert…') : sanitizeFilename(file.name) || t('Datei')}
          </span>
        </button>
        {!canStream && (
          <div className="file-missing">
            {t('Großer Anhang: Dieser Browser unterstützt keinen sicheren Streaming-Export.')}
          </div>
        )}
        {exportError && <div className="file-missing">{exportError}</div>}
      </div>
    );
  }
  if (state !== 'ready' || !url || !blob) {
    // Reserve some space for still-media so lazy loading doesn't jump the scroll.
    const media = file.mime.startsWith('image/') || file.mime.startsWith('video/');
    return (
      <div
        ref={anchorRef}
        className="file-loading"
        aria-busy={near}
        style={media ? { minHeight: 160, minWidth: 120 } : undefined}
      >
        {state === 'loading' ? t('Anhang lädt…') : ''}
      </div>
    );
  }

  if (isSticker(file) && mayRenderInlineImage(file.mime, blob.size)) {
    return <img className="bubble-sticker" src={url} alt="Sticker" draggable={false} onClick={() => onStickerZoom(file)} />;
  }
  if (file.mime.startsWith('video/')) {
    return <video className="bubble-video" src={url} controls playsInline preload="metadata" />;
  }
  if (mayRenderInlineImage(file.mime, blob.size)) {
    return <img className="bubble-img" src={url} alt={sanitizeFilename(file.name)} draggable={false} onClick={() => onImageZoom(blob)} />;
  }
  if (file.mime.startsWith('audio/')) {
    return <AudioPlayer blob={blob} mime={file.mime} />;
  }
  return (
    <button className="file-chip" onClick={() => downloadBlob(blob, sanitizeFilename(file.name))}>
      <IconAttach size={15} />
      <span className="fn">{sanitizeFilename(file.name) || t('Datei')}</span>
    </button>
  );
}
