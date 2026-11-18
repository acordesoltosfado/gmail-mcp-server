import { randomBytes } from "node:crypto";

// ---------------------------------------------------------------------------
// forward_email helpers: recipient allowlist and MIME building.
// Pure functions (no Gmail calls) so they can be tested offline.
// ---------------------------------------------------------------------------

/** Gmail rejects messages above ~25 MB once encoded; stay under it. */
export const MAX_FORWARD_BYTES = 25 * 1024 * 1024;
export const MAX_FORWARD_RECIPIENTS = 5;

export interface Allowlist {
  emails: Set<string>;
  domains: Set<string>;
}

/**
 * Parses FORWARD_ALLOWLIST: comma or space separated entries.
 * "name@example.com" allows that exact address.
 * "@example.com" or "example.com" allows any address at exactly that domain (not subdomains).
 */
export function parseAllowlist(raw: string | undefined): Allowlist {
  const emails = new Set<string>();
  const domains = new Set<string>();
  for (const entry of (raw ?? "").split(/[\s,;]+/)) {
    const e = entry.trim().toLowerCase();
    if (!e) continue;
    if (e.startsWith("@")) domains.add(e.slice(1));
    else if (e.includes("@")) emails.add(e);
    else domains.add(e);
  }
  return { emails, domains };
}

const ADDRESS_RE = /^[^\s@<>()",;:\\[\]]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;

/** "Name <a@b.com>" or "a@b.com" -> "a@b.com" (lowercase), or null if not a single valid address. */
export function bareAddress(value: string): string | null {
  if (/[\r\n]/.test(value)) return null;
  const m = /<([^<>]+)>\s*$/.exec(value);
  const addr = (m ? m[1] : value).trim().toLowerCase();
  return ADDRESS_RE.test(addr) ? addr : null;
}

/**
 * Returns the bare recipient addresses, or throws when the allowlist is empty,
 * an address is invalid, or an address is not allowed.
 */
export function checkRecipients(recipients: string[], allow: Allowlist): string[] {
  if (allow.emails.size === 0 && allow.domains.size === 0) {
    throw new Error(
      "Forwarding is disabled: the server owner has not set FORWARD_ALLOWLIST in .env."
    );
  }
  if (recipients.length === 0) throw new Error("Pass at least one recipient in 'to'.");
  if (recipients.length > MAX_FORWARD_RECIPIENTS) {
    throw new Error(`At most ${MAX_FORWARD_RECIPIENTS} recipients per forward.`);
  }
  const out: string[] = [];
  const refused: string[] = [];
  for (const r of recipients) {
    const addr = bareAddress(r);
    if (!addr) throw new Error(`Not a single valid email address: ${JSON.stringify(r)}`);
    const domain = addr.split("@")[1];
    if (allow.emails.has(addr) || allow.domains.has(domain)) {
      if (!out.includes(addr)) out.push(addr);
    } else refused.push(addr);
  }
  if (refused.length) {
    throw new Error(
      `Refused: ${refused.join(", ")} not in the server's forwarding allowlist. Nothing was sent.`
    );
  }
  return out;
}

/**
 * Sender check for FORWARD_ALLOWED_SENDERS. A From header is trivial to fake, so the
 * sender must also pass DMARC according to Gmail's own Authentication-Results header
 * (the first one, which Gmail adds on receipt; any lower ones could be forged by the sender).
 * Throws when the message may not be forwarded.
 */
export function checkSender(
  fromHeader: string,
  firstAuthResults: string,
  allow: Allowlist
): string {
  const from = bareAddress(fromHeader);
  if (!from) throw new Error(`Refused: could not read the sender address (${JSON.stringify(fromHeader)}).`);
  const domain = from.split("@")[1];
  if (!allow.emails.has(from) && !allow.domains.has(domain)) {
    throw new Error(`Refused: ${from} is not an allowed sender for forwarding. Nothing was sent.`);
  }
  const ar = firstAuthResults.toLowerCase();
  const fromDomain = /header\.from=([a-z0-9.-]+)/.exec(ar)?.[1];
  if (!/^\s*mx\.google\.com\b/.test(ar) || !/\bdmarc=pass\b/.test(ar) || fromDomain !== domain) {
    throw new Error(
      `Refused: Gmail could not verify that this email really comes from ${domain} (DMARC did not pass). It may be spoofed. Nothing was sent.`
    );
  }
  return from;
}

// ---------------------------------------------------------------------------
// MIME
// ---------------------------------------------------------------------------

export interface ForwardAttachment {
  filename: string;
  mimeType: string;
  contentId?: string;
  inline?: boolean;
  data: Buffer;
}

export interface ForwardMimeInput {
  to: string[];
  original: {
    from: string;
    date: string;
    subject: string;
    to: string;
    cc: string;
    messageId: string;
    references: string;
  };
  note?: string;
  plain?: string;
  html?: string;
  attachments: ForwardAttachment[];
}

/** Header values from the original email are single-line; never let a line break through. */
function oneLine(v: string): string {
  return v.replace(/[\r\n]+/g, " ").trim();
}

function encodeHeader(value: string): string {
  return /^[\x20-\x7e]*$/.test(value)
    ? value
    : `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
}

function b64Lines(buf: Buffer): string {
  return buf.toString("base64").replace(/.{76}/g, "$&\r\n");
}

function textPart(type: "text/plain" | "text/html", content: string): string[] {
  return [
    `Content-Type: ${type}; charset="UTF-8"`,
    "Content-Transfer-Encoding: base64",
    "",
    b64Lines(Buffer.from(content, "utf8")),
  ];
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Rough HTML -> text, used only when the original has no plain-text version. */
export function htmlToText(html: string): string {
  return html
    .replace(/<(style|script|head)[\s\S]*?<\/\1>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function forwardSubject(subject: string): string {
  const s = oneLine(subject);
  return /^(fwd?|enc|wg|tr):/i.test(s) ? s : `Fwd: ${s}`;
}

function boundary(): string {
  return `fwd_${randomBytes(12).toString("hex")}`;
}

function safeFilename(name: string): string {
  return oneLine(name).replace(/["\\]/g, "_") || "attachment";
}

function attachmentPart(a: ForwardAttachment): string[] {
  const type = /^[\w.+-]+\/[\w.+-]+$/.test(a.mimeType) ? a.mimeType : "application/octet-stream";
  const name = safeFilename(a.filename);
  const ascii = /^[\x20-\x7e]*$/.test(name);
  const nameParam = ascii
    ? `filename="${name}"`
    : `filename="${encodeHeader(name)}"; filename*=UTF-8''${encodeURIComponent(name)}`;
  const cid = a.contentId?.replace(/[<>\s]/g, "");
  return [
    `Content-Type: ${type}; name="${ascii ? name : encodeHeader(name)}"`,
    `Content-Disposition: ${a.inline ? "inline" : "attachment"}; ${nameParam}`,
    "Content-Transfer-Encoding: base64",
    ...(cid && /^[\w.@$+-]+$/.test(cid) ? [`Content-ID: <${cid}>`] : []),
    "",
    b64Lines(a.data),
  ];
}

/** Builds a Gmail-style inline forward: note, forwarded header block, original body, attachments. */
export function buildForwardMime(input: ForwardMimeInput): string {
  const o = input.original;
  const note = input.note?.trim() ?? "";

  const block = [
    "---------- Forwarded message ---------",
    `From: ${oneLine(o.from)}`,
    `Date: ${oneLine(o.date)}`,
    `Subject: ${oneLine(o.subject)}`,
    `To: ${oneLine(o.to)}`,
    ...(o.cc ? [`Cc: ${oneLine(o.cc)}`] : []),
  ];

  const originalPlain = input.plain ?? (input.html ? htmlToText(input.html) : "");
  const plain = [...(note ? [note, ""] : []), ...block, "", originalPlain].join("\n");

  let body: string[];
  if (input.html) {
    const htmlBlock = block.map(escapeHtml).join("<br>");
    const html = [
      note ? `<div>${escapeHtml(note).replace(/\n/g, "<br>")}</div><br>` : "",
      `<div class="gmail_quote">${htmlBlock}<br><br>`,
      input.html,
      "</div>",
    ].join("");
    const b = boundary();
    body = [
      `Content-Type: multipart/alternative; boundary="${b}"`,
      "",
      `--${b}`,
      ...textPart("text/plain", plain),
      `--${b}`,
      ...textPart("text/html", html),
      `--${b}--`,
    ];
  } else {
    body = textPart("text/plain", plain);
  }

  const references = [oneLine(o.references), oneLine(o.messageId)].filter(Boolean).join(" ");
  const headers = [
    `To: ${input.to.join(", ")}`,
    `Subject: ${encodeHeader(forwardSubject(o.subject))}`,
    "MIME-Version: 1.0",
    ...(references ? [`References: ${references}`] : []),
  ];

  let mime: string[];
  if (input.attachments.length) {
    const b = boundary();
    mime = [
      ...headers,
      `Content-Type: multipart/mixed; boundary="${b}"`,
      "",
      `--${b}`,
      ...body,
      ...input.attachments.flatMap((a) => [`--${b}`, ...attachmentPart(a)]),
      `--${b}--`,
      "",
    ];
  } else {
    mime = [...headers, ...body, ""];
  }
  return mime.join("\r\n");
}
