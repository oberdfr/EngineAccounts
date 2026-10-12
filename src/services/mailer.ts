import nodemailer, { type Transporter } from 'nodemailer';
import type { Config } from '../config.js';
import { createLogger } from '../logger.js';

const logger = createLogger((process.env.LOG_LEVEL as never) ?? 'info', { svc: 'engine-accounts' });

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface Mailer {
  send(message: MailMessage): Promise<void>;
  /** Solo per i test: messaggi inviati. */
  readonly sent?: MailMessage[];
}

export class SmtpMailer implements Mailer {
  private readonly transporter: Transporter;

  constructor(private readonly config: Config) {
    this.transporter = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE,
      auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined,
      // In sviluppo il relay accetta qualsiasi mittente: niente autenticazione.
      ignoreTLS: !config.SMTP_USER,
      tls: { rejectUnauthorized: config.NODE_ENV === 'production' },
    });
  }

  async send(message: MailMessage): Promise<void> {
    await this.transporter.sendMail({
      from: { name: this.config.SMTP_FROM_NAME, address: this.config.SMTP_FROM },
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
    logger.info('email inviata', { to: maskEmail(message.to), subject: message.subject });
  }
}

/** Non invia: log minimali. Per ambienti senza posta. */
export class DisabledMailer implements Mailer {
  async send(message: MailMessage): Promise<void> {
    logger.info('posta disabilitata, messaggio scartato', { to: maskEmail(message.to), subject: message.subject });
  }
}

/** Cattura in memoria: usato dai test per non dipendere da Mailpit. */
export class InMemoryMailer implements Mailer {
  readonly sent: MailMessage[] = [];
  async send(message: MailMessage): Promise<void> {
    this.sent.push(message);
  }
  lastTo(to: string): MailMessage | undefined {
    return [...this.sent].reverse().find((m) => m.to === to);
  }
  clear(): void {
    this.sent.length = 0;
  }
}

export function mailerFromConfig(config: Config, override?: Mailer): Mailer {
  if (override) return override;
  return config.MAIL_ENABLED ? new SmtpMailer(config) : new DisabledMailer();
}

export function maskEmail(email: string): string {
  const [user = '', domain = ''] = email.split('@');
  if (!domain) return '***';
  return `${user.slice(0, 2)}***@${domain}`;
}