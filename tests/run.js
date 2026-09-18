'use strict';
const lib = require('../email-auth-headers.js');

let pass = 0, fail = 0;
function eq(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) pass++;
  else { fail++; console.log('FAIL ' + name + '\n  got  ' + g + '\n  want ' + w); }
}
const H = lines => lines.join('\n');

// 1. The phishing sample shown on the live tool: DMARC fails.
const phish = H([
  'Received: by 2002:a05:6402:1234 with SMTP id k20csp123456;',
  '        Fri, 12 Sep 2026 03:14:22 -0700 (PDT)',
  'Received: from mail-relay.megacorp-invoices.test (mail-relay.megacorp-invoices.test. [198.51.100.77])',
  '        by mx.google.com with ESMTPS id p12si987654',
  '        for <you@example.com>;',
  '        Fri, 12 Sep 2026 03:14:20 -0700 (PDT)',
  'Received: from localhost (unknown [203.0.113.19])',
  '        by mail-relay.megacorp-invoices.test (Postfix) with ESMTPA id 4XyZ;',
  '        Fri, 12 Sep 2026 09:47:55 +0000 (UTC)',
  'Authentication-Results: mx.google.com;',
  '       dkim=pass header.i=@megacorp-invoices.test header.s=default;',
  '       spf=pass (google.com: domain of bounce@megacorp-invoices.test designates 198.51.100.77 as permitted sender) smtp.mailfrom=bounce@megacorp-invoices.test;',
  '       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=megacorp.example',
  'DKIM-Signature: v=1; a=rsa-sha256; d=megacorp-invoices.test; s=default;',
  'Return-Path: <bounce@megacorp-invoices.test>',
  'From: "MegaCorp Billing" <billing@megacorp.example>',
  'Reply-To: recovery-desk@mail.test',
  'Subject: =?UTF-8?B?T3ZlcmR1ZSBpbnZvaWNlIOKAlCBhY3Rpb24gcmVxdWlyZWQ=?=',
  'Date: Fri, 12 Sep 2026 09:47:55 +0000',
  '',
  'Body text: From: nobody@evil.test'
]);
let r = lib.analyze(phish);
eq('phish verdict', r.verdict.tag, 'Failed checks');
eq('phish auth', [r.auth.spf, r.auth.dkim, r.auth.dmarc], ['pass', 'pass', 'fail']);
eq('phish subject decoded', r.message.subject, 'Overdue invoice — action required');
eq('phish origin ip (oldest public hop)', r.route.originIp, '203.0.113.19');
eq('phish hops', r.route.hops.length, 3);
eq('body is not parsed as headers', r.headers.some(h => /nobody@evil/.test(h.value)), false);
eq('reply-to flagged', r.findings.warn.some(w => /Replies would go to mail\.test/.test(w)), true);

// 2. A legitimate newsletter sent through an email provider.
//    This exact shape was wrongly rated "Suspicious" by the old tool.
const newsletter = H([
  'Received: from mail123.us5.mcsv.net (mail123.us5.mcsv.net [198.2.130.10])',
  '        by mx.example.com with ESMTPS; Mon, 14 Sep 2026 10:00:02 +0000',
  'Authentication-Results: mx.example.com;',
  '       dkim=pass header.i=@shop.example header.s=k1;',
  '       dkim=pass header.i=@mailchimpapp.net header.s=k3;',
  '       spf=pass (example.com: domain of bounce-mc.us5_123@mail123.us5.mcsv.net designates 198.2.130.10 as permitted sender) smtp.mailfrom=bounce-mc.us5_123@mail123.us5.mcsv.net;',
  '       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=shop.example',
  'Return-Path: <bounce-mc.us5_123@mail123.us5.mcsv.net>',
  'From: Shop <news@shop.example>',
  'Subject: This week at Shop'
]);
r = lib.analyze(newsletter);
eq('newsletter verdict', r.verdict.tag, 'Looks genuine');
eq('newsletter has no warnings', r.findings.warn, []);
eq('envelope difference is info, not a warning', r.findings.info.length, 1);
eq('aligned DKIM found among several', r.domains.dkim, ['shop.example', 'mailchimpapp.net']);

// 3. Subdomain sender: relaxed alignment means mail.shop.example aligns with shop.example.
const sub = H([
  'Received: from out.mail.shop.example (out.mail.shop.example [198.51.100.5]) by mx.example.com; Mon, 14 Sep 2026 10:00:00 +0000',
  'Authentication-Results: mx.example.com; dkim=pass header.d=mail.shop.example; spf=pass smtp.mailfrom=bounce@mail.shop.example; dmarc=pass header.from=shop.example',
  'Return-Path: <bounce@mail.shop.example>',
  'From: <orders@shop.example>'
]);
r = lib.analyze(sub);
eq('subdomain verdict', r.verdict.tag, 'Looks genuine');
eq('subdomain: nothing to report', r.findings.info.concat(r.findings.warn), []);

// 4. Only the topmost Authentication-Results counts: a forged "pass" lower down is ignored.
const forged = H([
  'Received: from evil.test (evil.test [203.0.113.66]) by mx.example.com; Mon, 14 Sep 2026 10:00:00 +0000',
  'Authentication-Results: mx.example.com; spf=none smtp.mailfrom=evil.test; dkim=none; dmarc=none header.from=bank.example',
  'Authentication-Results: mx.example.com; spf=pass; dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example',
  'From: Bank <security@bank.example>'
]);
r = lib.analyze(forged);
eq('forged lower header ignored', [r.auth.spf, r.auth.dkim, r.auth.dmarc], ['none', 'none', 'none']);
eq('forged verdict is not genuine', r.verdict.level !== 'pass', true);

// 5. No Authentication-Results at all: fall back to Received-SPF, and warn about DMARC.
const noar = H([
  'Received-SPF: softfail (example.com: transitioning domain of x@other.example does not designate 203.0.113.9 as permitted sender) envelope-from=x@other.example;',
  'From: <ceo@company.example>',
  'Subject: urgent'
]);
r = lib.analyze(noar);
eq('received-spf fallback', r.auth.spf, 'softfail');
eq('auth source', r.auth.source, 'Received-SPF');
eq('no-AR verdict', r.verdict.tag, 'Suspicious');

// 6. DKIM fails but another passes and DMARC passes: authenticated.
r = lib.analyze(H([
  'Authentication-Results: mx.test; dkim=fail header.d=old.shop.example; dkim=pass header.d=shop.example; spf=pass smtp.mailfrom=shop.example; dmarc=pass header.from=shop.example',
  'From: <a@shop.example>'
]));
eq('any passing DKIM counts', r.auth.dkim, 'pass');
eq('mixed DKIM verdict', r.verdict.tag, 'Looks genuine');

// 7. Reply-To elsewhere, everything else fine: one thing to check.
r = lib.analyze(H([
  'Authentication-Results: mx.test; dkim=pass header.d=shop.example; spf=pass smtp.mailfrom=shop.example; dmarc=pass header.from=shop.example',
  'From: <a@shop.example>',
  'Reply-To: <help@support-desk.example>'
]));
eq('reply-to only', r.verdict.tag, 'Worth a look');

// --- helpers ---
eq('orgDomain plain', lib.orgDomain('a.b.shop.example'), 'shop.example');
eq('orgDomain co.uk', lib.orgDomain('mail.bbc.co.uk'), 'bbc.co.uk');
eq('orgDomain com.au', lib.orgDomain('x.shop.com.au'), 'shop.com.au');
eq('aligned', [lib.aligned('mail.shop.example', 'shop.example'), lib.aligned('shop.example', 'shop.test')], [true, false]);
eq('domainOf display name', lib.domainOf('"Billing Dept" <billing@Shop.Example>'), 'shop.example');
eq('domainOf bare', lib.domainOf('<bounce@mail.shop.example>'), 'mail.shop.example');
eq('Q encoding', lib.decodeWords('=?utf-8?Q?Caf=C3=A9_menu?='), 'Café menu');
eq('adjacent words join', lib.decodeWords('=?UTF-8?B?SGVsbG8g?= =?UTF-8?B?d29ybGQ=?='), 'Hello world');
eq('bad encoding left alone', lib.decodeWords('=?x-nope?B?###?='), '=?x-nope?B?###?=');
eq('public IPs skip private/CGNAT', lib.publicIPs('from x [10.0.0.1] via [100.64.1.1] then [198.51.100.9] [198.51.100.9]'), ['198.51.100.9']);
eq('not headers', lib.analyze('hello').ok, false);

// The library is pasted into WordPress, which mangles this character inside <script>.
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'email-auth-headers.js'), 'utf8');
eq('no ampersand in the library source', src.indexOf(String.fromCharCode(38)), -1);

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
