// Run: npx tsx test/forward.test.ts  (no network, no Gmail)
import assert from "node:assert/strict";
import {
  bareAddress,
  buildForwardMime,
  checkRecipients,
  checkSender,
  forwardSubject,
  parseAllowlist,
} from "../src/forward.js";

// --- allowlist parsing
const allow = parseAllowlist(" bookings@bokun.example , @partner.example;other.example ");
assert.ok(allow.emails.has("bookings@bokun.example"));
assert.ok(allow.domains.has("partner.example"));
assert.ok(allow.domains.has("other.example"));

// --- addresses
assert.equal(bareAddress("Bókun <Bookings@Bokun.example>"), "bookings@bokun.example");
assert.equal(bareAddress("a@b.example\r\nBcc: x@y.example"), null);
assert.equal(bareAddress("a@b.example, c@d.example"), null);

// --- recipients
assert.deepEqual(checkRecipients(["Bookings@bokun.example"], allow), ["bookings@bokun.example"]);
assert.deepEqual(checkRecipients(["x@partner.example"], allow), ["x@partner.example"]);
assert.throws(() => checkRecipients(["x@sub.partner.example"], allow), /Refused/);
assert.throws(() => checkRecipients(["bookings@bokun.example", "evil@evil.example"], allow), /Refused: evil@evil.example/);
assert.throws(() => checkRecipients(["bookings@bokun.example"], parseAllowlist("")), /disabled/);
assert.throws(() => checkRecipients(["bookings@bokun.example"], parseAllowlist(undefined)), /disabled/);

// --- senders + DMARC
const senders = parseAllowlist("partners@feverup.com,noreply@order.eventbrite.com");
const goodAR = "mx.google.com; dkim=pass header.i=@feverup.com; spf=pass; dmarc=pass (p=REJECT) header.from=feverup.com";
assert.equal(checkSender("Fever <partners@feverup.com>", goodAR, senders), "partners@feverup.com");
assert.throws(() => checkSender("Fever <partners@feverup.com>", goodAR.replace("dmarc=pass", "dmarc=fail"), senders), /spoofed/);
assert.throws(() => checkSender("Fever <partners@feverup.com>", "", senders), /spoofed/);
assert.throws(() => checkSender("Fever <partners@feverup.com>", "evil.example; dmarc=pass header.from=feverup.com", senders), /spoofed/);
assert.throws(() => checkSender("someone@feverup.com", goodAR, senders), /not an allowed sender/);
const ebAR = "mx.google.com; dmarc=pass (p=NONE) header.from=order.eventbrite.com";
assert.equal(checkSender("noreply@order.eventbrite.com", ebAR, senders), "noreply@order.eventbrite.com");

// --- subject
assert.equal(forwardSubject("Booking #42"), "Fwd: Booking #42");
assert.equal(forwardSubject("Fwd: Booking #42"), "Fwd: Booking #42");

// --- MIME
const original = {
  from: "Fever <partners@feverup.com>",
  date: "Tue, 17 Nov 2026 10:00:00 +0000",
  subject: "Reserva confirmada\r\nBcc: evil@evil.example",
  to: "me@example.com",
  cc: "",
  messageId: "<abc@feverup.com>",
  references: "",
};
const mime = buildForwardMime({
  to: ["bookings@bokun.example"],
  original,
  note: "Nova reserva",
  html: "<p>Hello <b>there</b></p>",
  attachments: [{ filename: "ticket.pdf", mimeType: "application/pdf", data: Buffer.from("%PDF-1") }],
});
const headerPart = mime.split("\r\n\r\n")[0];
assert.ok(!/^Bcc:/im.test(headerPart), "no injected header");
assert.match(headerPart, /^To: bookings@bokun\.example$/m);
assert.match(headerPart, /^References: <abc@feverup\.com>$/m);
assert.match(headerPart, /multipart\/mixed/);
assert.match(mime, /multipart\/alternative/);
assert.match(mime, /Content-Disposition: attachment; filename="ticket.pdf"/);
assert.ok(mime.includes(Buffer.from("%PDF-1").toString("base64")));
// The plain part is generated from HTML when there is no plain version
const plainB64 = /text\/plain; charset="UTF-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n([\s\S]+?)\r\n--/.exec(mime)![1];
const plain = Buffer.from(plainB64.replace(/\r\n/g, ""), "base64").toString("utf8");
assert.match(plain, /^Nova reserva\n\n---------- Forwarded message ---------\nFrom: Fever <partners@feverup\.com>/);
assert.match(plain, /Hello there/);

console.log("forward tests: OK");
