// Run: npx tsx test/forward-flow.test.ts  (fake Gmail, no network)
import assert from "node:assert/strict";
import { GmailService } from "../src/gmail-service.js";
import { parseAllowlist } from "../src/forward.js";

const b64u = (s: string) => Buffer.from(s).toString("base64url");
const message = {
  id: "m1",
  threadId: "t1",
  payload: {
    mimeType: "multipart/mixed",
    headers: [
      { name: "Authentication-Results", value: "mx.google.com; dmarc=pass (p=REJECT) header.from=feverup.com" },
      { name: "From", value: "Fever <partners@feverup.com>" },
      { name: "To", value: "me@example.com" },
      { name: "Subject", value: "Booking confirmed" },
      { name: "Date", value: "Tue, 17 Nov 2026 10:00:00 +0000" },
      { name: "Message-ID", value: "<abc@feverup.com>" },
      // A forged lower header must be ignored
      { name: "Authentication-Results", value: "mx.google.com; dmarc=pass header.from=evil.example" },
    ],
    parts: [
      {
        mimeType: "multipart/alternative",
        parts: [
          { mimeType: "text/plain", filename: "", body: { data: b64u("Plain booking text") } },
          { mimeType: "text/html", filename: "", body: { data: b64u("<p>HTML booking</p>") } },
        ],
      },
      { mimeType: "application/pdf", filename: "ticket.pdf", headers: [{ name: "Content-Disposition", value: "attachment" }], body: { attachmentId: "att1" } },
    ],
  },
};

let sent: any;
const fake = {
  users: {
    messages: {
      get: async () => ({ data: message }),
      attachments: { get: async () => ({ data: { data: b64u("%PDF-1.7 fake") } }) },
      send: async (req: any) => { sent = req; return { data: { id: "s1", threadId: "t1" } }; },
    },
    drafts: { create: async (req: any) => { sent = req; return { data: { id: "d1", message: { id: "m2", threadId: "t1" } } }; } },
  },
};

const svc = new GmailService("fake-token");
(svc as any).gmail = fake;
const senders = parseAllowlist("partners@feverup.com,noreply@order.eventbrite.com");

const r = await svc.forwardEmail("m1", ["bookings@bokun.example"], { note: "hi", allowedSenders: senders });
assert.equal(r.id, "s1");
assert.deepEqual(r.attachments, ["ticket.pdf"]);
assert.equal(r.subject, "Fwd: Booking confirmed");
assert.equal(sent.media.mimeType, "message/rfc822");
assert.equal(sent.requestBody.threadId, "t1");
assert.match(sent.media.body, /filename="ticket.pdf"/);
assert.ok(sent.media.body.includes(Buffer.from("%PDF-1.7 fake").toString("base64")));

const d = await svc.forwardEmail("m1", ["bookings@bokun.example"], { draft: true, allowedSenders: senders });
assert.equal(d.draftId, "d1");
assert.equal(sent.requestBody.message.threadId, "t1");

// Sender not on the list -> refused before anything is sent
sent = undefined;
await assert.rejects(
  svc.forwardEmail("m1", ["bookings@bokun.example"], { allowedSenders: parseAllowlist("other@x.example") }),
  /not an allowed sender/
);
assert.equal(sent, undefined);

console.log("forward flow tests: OK");
