# email-auth-headers

Paste raw email headers, get a plain-English answer: **did this message authenticate, where did it
come from, and does anything look forged?**

One dependency-free file, no network access. Browser and Node 18+. It powers the
[Email Header Analyzer on ExamineIP](https://tools.examineip.com/email-header-analyzer/).

```
$ node email-auth-headers.js tests/newsletter.txt

LOOKS GENUINE — Authentication passed and the sender checks out
SPF pass · DKIM pass · DMARC pass
  [info] The envelope sender (mail123.us5.mcsv.net) is a different domain from the visible From (shop.example). Normal when mail is sent through an email provider.
  [good] DMARC passed: the visible sender domain (shop.example) is the one that authenticated.
Origin IP: 198.2.130.10 (1 hops)
```

---

## The mistakes this avoids

Header analyzers are easy to write and easy to get subtly wrong. These are the ones this library was
built to fix — including two that were in our own tool until September 2026:

| Mistake | Effect | What this library does |
|---|---|---|
| **Treating every domain mismatch as suspicious** | Newsletters and receipts sent through Mailchimp, SendGrid, Amazon SES etc. use the provider's bounce and signing domains, so almost all legitimate bulk mail gets flagged | When DMARC passes, envelope/DKIM/Return-Path differences are reported as *info*, not warnings — the receiving server already checked alignment |
| **Exact-string domain comparison** | `mail.shop.example` "doesn't match" `shop.example` | DMARC relaxed alignment: compares organisational domains (`co.uk`, `com.au` style suffixes handled) |
| **Reading every Authentication-Results header** | A forger can add their own `Authentication-Results: … dkim=pass` below the real one; the first regex match anywhere wins | Only the **topmost** header counts — the one your own mail provider added |
| First DKIM result only | A message with one stale failing signature and one valid one reads as "DKIM fail" | Any passing DKIM signature counts, as in DMARC |
| Parsing into the body | Text like `From: …` in the body is read as a header | Parsing stops at the first blank line |
| Private and CGNAT addresses as "origin" | The origin IP is a 10.x or 100.64.x address | Only public IPv4 addresses are used for the route |

A **Reply-To** on a different organisational domain from **From** stays a warning even when everything
passes — that's how many phishing messages harvest replies — but it's worded as "worth a look", since
some companies use a separate support domain.

---

## Use it

```js
const { analyze } = require('./email-auth-headers');   // browser: <script src> → window.emailAuthHeaders

const r = analyze(rawHeaders);
r.verdict;    // { level: 'pass' | 'warn' | 'fail', tag: 'Looks genuine' | 'Worth a look' | 'Suspicious' | 'Failed checks', title }
r.findings;   // { bad: [], warn: [], info: [], good: [] } — plain-English sentences
r.auth;       // { spf, dkim, dmarc, dkimResults: [{result, domain}], authservId, source }
r.domains;    // { from, envelope, returnPath, replyTo, dkim: [], orgFrom }
r.message;    // { from, subject (RFC 2047 decoded), date, messageId, returnPath }
r.route;      // { hops: [{from, by, ips, time}], originIp, transitMs }  — oldest hop first
```

CLI: `node email-auth-headers.js headers.txt [--json]` or pipe headers on stdin. Exit code `2` if
authentication failed.

Helpers: `parse`, `decodeWords`, `domainOf`, `orgDomain`, `aligned`, `parseAuthResults`, `authResults`,
`publicIPs`, `route`.

---

## What it can't tell you

- **Whether the message is safe.** A scammer with their own domain passes SPF, DKIM and DMARC perfectly.
  Authentication proves *which domain* sent it, not that the domain is honest — check the domain itself
  (a [WHOIS lookup](https://tools.examineip.com/whois-lookup/) shows how new it is).
- **Headers your provider didn't add.** Everything below the first server your provider controls travelled
  with the message and could be invented.
- **Exact Public Suffix List behaviour.** Organisational domains use a built-in approximation of the PSL,
  which covers the common two-level country suffixes but not every private suffix.

---

## Why no ampersands?

The same file is pasted into a WordPress page, and WordPress HTML-encodes `&` inside `<script>` on save,
turning `&&` into a syntax error that silently kills the whole script. The source avoids the character
entirely — conditions use nested ternaries or early returns instead. Odd, but deliberate.

---

## Tests

```
node tests/run.js
```

Offline fixtures: a phishing message that fails DMARC, a provider-sent newsletter, a subdomain sender,
a forged lower Authentication-Results header, Received-SPF fallback, mixed DKIM results, Reply-To
mismatch, RFC 2047 B/Q decoding, and the domain helpers. CI runs on Node 18, 20 and 22.

---

## Licence

MIT — see [LICENSE](LICENSE).

Built by [ExamineIP](https://examineip.com/). Try it in the browser at the
[Email Header Analyzer](https://tools.examineip.com/email-header-analyzer/) — nothing is uploaded.
