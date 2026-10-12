/**
 * Template transazionali. Testo semplice: nessun layout, nessun CSS inline
 * (le email non sono pagine web, ma restiamo sobri anche li').
 */

import type { Config } from '../config.js';

export interface TemplateContext {
  config: Config;
  /** Assente per i template senza link (codice di accesso). */
  actionUrl?: string;
  code?: string;
  minutes?: number;
}

/**
 * `actionUrl` e' obbligatorio nei template con link: la firma lo rende
 * esplicito e il fallimento e' un errore di programmazione, non un invariante
 * controllata a runtime.
 */
type ActionTemplate = TemplateContext & { actionUrl: string };

function layout(title: string, paragraphs: string[], action?: { label: string; url: string }): {
  text: string;
  html: string;
} {
  const text = [
    title,
    '',
    ...paragraphs,
    ...(action ? ['', `${action.label}: ${action.url}`] : []),
    '',
    'Se non hai chiesto tu questa operazione, ignora questo messaggio.',
  ].join('\n');

  const html = [
    '<!doctype html><html lang="it"><head><meta charset="utf-8">',
    `<title>${escapeHtml(title)}</title></head>`,
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#1b1b1b;max-width:34rem;margin:2rem auto;padding:0 1rem">',
    `<h1 style="font-size:1.25rem">${escapeHtml(title)}</h1>`,
    ...paragraphs.map((p) => `<p>${escapeHtml(p)}</p>`),
    ...(action
      ? [
          `<p><a href="${escapeHtml(action.url)}" style="display:inline-block;background:#19ad79;color:#0b0b0b;padding:.6rem 1rem;border-radius:.4rem;text-decoration:none">${escapeHtml(action.label)}</a></p>`,
          `<p style="font-size:.85rem;color:#555">Se il collegamento non funziona, copia questo indirizzo:<br><code>${escapeHtml(action.url)}</code></p>`,
        ]
      : []),
    '<hr>',
    '<p style="font-size:.85rem;color:#555">Se non hai chiesto tu questa operazione, ignora questo messaggio.</p>',
    '</body></html>',
  ].join('');

  return { text, html };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export function verifyEmailTemplate({ config, actionUrl, minutes = 15 }: ActionTemplate) {
  return {
    subject: 'Conferma il tuo indirizzo email',
    ...layout(
      'Conferma la tua email',
      [
        `Hai creato un account su ${config.issuer}.`,
        `Questo link vale ${minutes} minuti e puo\` essere usato una volta sola.`,
      ],
      { label: 'Conferma indirizzo', url: actionUrl },
    ),
  };
}

export function passwordResetTemplate({ config, actionUrl, minutes = 15 }: ActionTemplate) {
  return {
    subject: 'Reimposta la password',
    ...layout(
      'Reimposta la password',
      [
        `Hai chiesto di reimpostare la password del tuo account su ${config.issuer}.`,
        `Questo link vale ${minutes} minuti e puo\` essere usato una volta sola.`,
        'Se non sei tu, nessuna azione e\' necessaria: la password attuale resta valida.',
      ],
      { label: 'Scegli una nuova password', url: actionUrl },
    ),
  };
}

export function magicCodeTemplate({ config, code, minutes = 10 }: TemplateContext) {
  return {
    subject: `${code} e\' il tuo codice di accesso`,
    ...layout('Codice di accesso', [
      `Usalo per accedere a ${config.issuer}.`,
      `Vale ${minutes} minuti e serve una volta sola.`,
      `Se qualcuno ha accesso al tuo account, cambia la password.`,
    ]),
  };
}

export function emailChangeTemplate({ config, actionUrl, minutes = 15 }: ActionTemplate) {
  return {
    subject: 'Conferma il nuovo indirizzo email',
    ...layout(
      'Conferma il nuovo indirizzo',
      [
        'Hai chiesto di cambiare l\'indirizzo email del tuo account.',
        `Questo link vale ${minutes} minuti e puo\` essere usato una volta sola.`,
        'Se non sei tu, ignora questo messaggio: l\'indirizzo attuale resta attivo.',
      ],
      { label: 'Conferma nuovo indirizzo', url: actionUrl },
    ),
  };
}