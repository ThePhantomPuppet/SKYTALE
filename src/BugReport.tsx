import { useState } from 'react';
import { t, getLang } from './lib/i18n';

/**
 * Bug report / feedback. The dialog assembles a categorised report WITH a detailed,
 * strictly non-sensitive situation picture (device / environment / runtime — never
 * messages, contacts or keys) and hands the finished text to the Messenger, which
 * sends it as a normal end-to-end message to the official SKYTALE-SUPPORT account.
 * The admin therefore sees the ticket type at a glance and has everything needed to
 * reproduce, and can reply / ask follow-up questions in the very same chat.
 */
declare const __APP_VERSION__: string;
declare const __BUILD_HASH__: string;

// The leading emoji makes the ticket type scannable in the admin's chat list.
const CATEGORIES: { key: string; emoji: string; label: () => string }[] = [
  { key: 'bug', emoji: '🐛', label: () => t('Etwas funktioniert nicht') },
  { key: 'crash', emoji: '💥', label: () => t('Absturz / Fehler') },
  { key: 'idea', emoji: '💡', label: () => t('Vorschlag / Feedback') },
  { key: 'other', emoji: '❓', label: () => t('Sonstiges') },
];

/** Everything useful for reproducing an issue, and NOTHING sensitive: no messages,
 * no contacts, no keys, no usage counts — only device / environment / runtime. */
async function diagnostics(): Promise<string> {
  const L: string[] = [];
  const push = (k: string, v: unknown) => L.push(`${k}: ${v ?? '?'}`);
  const nav = navigator as Navigator & {
    connection?: { effectiveType?: string };
    deviceMemory?: number;
  };
  const mm = (q: string) => window.matchMedia?.(q).matches;
  const mb = (b: unknown) => (typeof b === 'number' ? `${Math.round(b / 1048576)} MB` : '?');
  try {
    push(
      'Version',
      `${typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : '?'}${typeof __BUILD_HASH__ !== 'undefined' ? '+' + __BUILD_HASH__ : ''}`,
    );
    push('App-Sprache', getLang());
    push('System-Sprache', nav.language);
    push('Plattform', nav.platform);
    push('Browser', nav.userAgent);
    push('Bildschirm', `${window.screen?.width ?? '?'}×${window.screen?.height ?? '?'} @${window.devicePixelRatio ?? 1}x`);
    push('Fenster', `${window.innerWidth}×${window.innerHeight}`);
    push('PWA (Standalone)', mm('(display-mode: standalone)') ? 'ja' : 'nein');
    push('Theme', mm('(prefers-color-scheme: dark)') ? 'dunkel' : 'hell');
    push('Reduzierte Bewegung', mm('(prefers-reduced-motion: reduce)') ? 'ja' : 'nein');
    push('Online', nav.onLine ? 'ja' : 'nein');
    push('Verbindung', nav.connection?.effectiveType);
    push('Gerätespeicher (RAM)', nav.deviceMemory ? `~${nav.deviceMemory} GB` : '?');
    push('CPU-Kerne', nav.hardwareConcurrency);
    push('Zeitzone', Intl.DateTimeFormat().resolvedOptions().timeZone);
    push('Datum', new Date().toISOString());
    push('Service Worker', nav.serviceWorker?.controller ? 'aktiv' : 'keiner');
    if (nav.storage?.estimate) {
      const est = await nav.storage.estimate();
      push('Speicher', `${mb(est.usage)} / ${mb(est.quota)} genutzt`);
    }
  } catch {
    /* best-effort */
  }
  return L.join('\n');
}

async function assembleReport(cat: string, msg: string, includeDiag: boolean): Promise<string> {
  const category = CATEGORIES.find((c) => c.key === cat) ?? CATEGORIES[0];
  const header = `${category.emoji} ${category.label()}`;
  const diag = includeDiag ? `\n\n— ${t('Geräte-Infos')} —\n${await diagnostics()}` : '';
  return `${header}\n\n${msg.trim()}${diag}`;
}

export function BugReport({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  /** Sends the finished report as a message to SKYTALE-SUPPORT; throws on failure. */
  onSubmit: (message: string) => Promise<void>;
}) {
  const [cat, setCat] = useState('bug');
  const [msg, setMsg] = useState('');
  // Default ON so the admin gets a detailed picture, but visible + opt-out: the
  // attached block is strictly device/environment info, never content.
  const [diag, setDiag] = useState(true);
  const [state, setState] = useState<'idle' | 'sending' | 'sent' | 'error'>('idle');

  async function send() {
    if (!msg.trim() || state === 'sending') return;
    setState('sending');
    try {
      await onSubmit(await assembleReport(cat, msg, diag));
      setState('sent');
      window.setTimeout(onClose, 1200);
    } catch {
      setState('error');
    }
  }

  async function copyInstead() {
    try {
      await navigator.clipboard.writeText(await assembleReport(cat, msg, diag));
    } catch {
      /* clipboard blocked */
    }
  }

  return (
    <div className="crop-modal" role="dialog" aria-label={t('Fehler melden')}>
      <div className="crop-head">{t('Fehler melden')}</div>
      <div className="backup-body">
        {state === 'sent' ? (
          <div className="info-note" style={{ textAlign: 'left' }}>
            <p>{t('Danke! Deine Meldung ist im Support-Chat — dort kannst du weiterschreiben.')}</p>
          </div>
        ) : (
          <>
            <p className="backup-hint" style={{ textAlign: 'left', marginTop: 0 }}>
              {t('Geht direkt an den SKYTALE-Support — du bekommst die Antwort in diesem Chat.')}
            </p>
            <div className="bug-cats">
              {CATEGORIES.map((c) => (
                <button
                  key={c.key}
                  type="button"
                  className={`bug-cat${cat === c.key ? ' on' : ''}`}
                  onClick={() => setCat(c.key)}
                >
                  {c.emoji} {c.label()}
                </button>
              ))}
            </div>
            <label className="backup-field">
              <span>{t('Was ist passiert?')}</span>
              <textarea
                className="bug-text"
                value={msg}
                maxLength={4000}
                autoFocus
                placeholder={t('Beschreibe den Fehler oder deine Idee — je genauer, desto besser.')}
                onChange={(e) => setMsg(e.target.value)}
              />
            </label>
            <label className="bug-diag">
              <input type="checkbox" checked={diag} onChange={(e) => setDiag(e.target.checked)} />
              <span>{t('Geräte-Infos für die Fehlersuche anhängen (Version, Browser, Speicher …) — nie Nachrichten, Kontakte oder Schlüssel.')}</span>
            </label>
            {state === 'error' && (
              <div className="err-note">
                {t('Senden fehlgeschlagen.')}{' '}
                <button type="button" className="linklike" onClick={() => void copyInstead()}>
                  {t('Stattdessen kopieren')}
                </button>
              </div>
            )}
          </>
        )}
      </div>
      {state !== 'sent' && (
        <div className="crop-actions">
          <button className="btn btn-ghost" onClick={onClose} disabled={state === 'sending'}>
            {t('Abbrechen')}
          </button>
          <button className="btn btn-primary" disabled={!msg.trim() || state === 'sending'} onClick={() => void send()}>
            {state === 'sending' ? '…' : t('Senden')}
          </button>
        </div>
      )}
    </div>
  );
}
