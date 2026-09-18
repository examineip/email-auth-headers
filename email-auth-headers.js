/*!
 * email-auth-headers — read raw email headers and explain whether the message
 * authenticated, where it came from, and whether anything looks forged.
 *
 * Pure JavaScript, no network, no dependencies. Browser and Node 18+.
 * This file deliberately contains no ampersand character: it is also pasted into
 * a WordPress Custom HTML block, and WordPress rewrites that character on save.
 * MIT License — https://github.com/examineip/email-auth-headers
 */
(function (root, factory) {
  if (typeof module === 'object' ? module.exports : false) module.exports = factory();
  else root.emailAuthHeaders = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ---------------- parsing ---------------- */

  /* RFC 5322 unfolding: a line that starts with whitespace continues the previous
   * header. Parsing stops at the first blank line (the start of the body). */
  function parse(raw) {
    var out = [], cur = null;
    var lines = String(raw || '').replace(/\r/g, '').split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^[ \t]/.test(line)) {
        if (cur) cur.value = (cur.value + ' ' + line.trim()).trim();
        continue;
      }
      if (line.trim() === '') {
        if (out.length) break;
        continue;
      }
      var m = /^([!-9;-~]+):[ \t]*(.*)$/.exec(line);
      if (m) {
        cur = { key: m[1], value: m[2].trim() };
        out.push(cur);
      } else {
        cur = null;
      }
    }
    return out;
  }

  function all(headers, key) {
    var k = key.toLowerCase();
    return headers.filter(function (h) { return h.key.toLowerCase() === k; })
      .map(function (h) { return h.value; });
  }
  function one(headers, key) {
    var v = all(headers, key);
    return v.length ? v[0] : null;
  }

  /* RFC 2047 encoded-words, e.g. =?UTF-8?B?...?= and =?UTF-8?Q?...?= */
  function decodeWords(s) {
    if (!s) return s;
    return String(s)
      .replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)/g, '$1')      // adjacent words join without the space
      .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, function (whole, charset, enc, data) {
        try {
          var bytes = [];
          if (enc.toUpperCase() === 'B') {
            var bin = atob(data.replace(/\s/g, ''));
            for (var i = 0; i < bin.length; i++) bytes.push(bin.charCodeAt(i));
          } else {
            var t = data.replace(/_/g, ' ');
            for (var j = 0; j < t.length; j++) {
              if (t[j] === '=' ? /^[0-9A-Fa-f]{2}$/.test(t.substr(j + 1, 2)) : false) {
                bytes.push(parseInt(t.substr(j + 1, 2), 16));
                j += 2;
              } else {
                bytes.push(t.charCodeAt(j));
              }
            }
          }
          return new TextDecoder(charset.toLowerCase()).decode(new Uint8Array(bytes));
        } catch (e) {
          return whole;
        }
      });
  }

  /* ---------------- domains ---------------- */

  function domainOf(s) {
    if (!s) return null;
    var str = String(s);
    var angle = /<([^>]*)>/.exec(str);
    if (angle) str = angle[1];
    var at = /@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/.exec(str);
    if (at) return at[1].toLowerCase().replace(/\.$/, '');
    var bare = /^\s*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\.?\s*$/.exec(str);
    return bare ? bare[1].toLowerCase() : null;
  }

  /* Second-level labels that act as public suffixes under a two-letter country
   * code (example.co.uk, example.com.au ...). This is an approximation of the
   * Public Suffix List, which is what DMARC formally uses; it covers the common
   * cases without shipping a 200 KB list. */
  var CC_SLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ltd', 'plc', 'ne', 'or', 'go', 'gob', 'nic', 'mil', 'biz', 'info'];

  function orgDomain(d) {
    if (!d) return null;
    var labels = String(d).toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    var tld = labels[labels.length - 1], sld = labels[labels.length - 2];
    var take = (tld.length === 2 ? CC_SLD.indexOf(sld) !== -1 : false) ? 3 : 2;
    return labels.slice(-take).join('.');
  }

  /* DMARC relaxed alignment: same organisational domain. */
  function aligned(a, b) {
    if (!a || !b) return false;
    return orgDomain(a) === orgDomain(b);
  }

  /* ---------------- authentication results ---------------- */

  /* Read method results out of ONE Authentication-Results header (RFC 8601).
   * Returns { authservId, spf, dkim: [{result, domain}], dmarc, mailfrom, headerFrom } */
  function parseAuthResults(value) {
    var v = String(value || '');
    var parts = v.split(';');
    var res = { authservId: parts[0].trim().split(/\s+/)[0] || null, spf: null, dkim: [], dmarc: null, mailfrom: null, headerFrom: null };
    for (var i = 1; i < parts.length; i++) {
      var p = parts[i].replace(/\([^)]*\)/g, ' ').trim();   // drop RFC 5322 comments
      var m = /^([a-z-]+)\s*=\s*([a-z]+)/i.exec(p);
      if (!m) continue;
      var method = m[1].toLowerCase(), result = m[2].toLowerCase();
      if (method === 'spf') {
        res.spf = result;
        var mf = /smtp\.mailfrom\s*=\s*"?([^\s;"]+)/i.exec(p);
        if (mf) res.mailfrom = domainOf(mf[1]) || domainOf('@' + mf[1]);
      } else if (method === 'dkim') {
        var d = /header\.(?:d|i)\s*=\s*@?([^\s;]+)/i.exec(p);
        res.dkim.push({ result: result, domain: d ? (domainOf('@' + d[1].replace(/^.*@/, '')) || d[1].toLowerCase()) : null });
      } else if (method === 'dmarc') {
        res.dmarc = result;
        var hf = /header\.from\s*=\s*([^\s;]+)/i.exec(p);
        if (hf) res.headerFrom = hf[1].toLowerCase();
      }
    }
    return res;
  }

  /* Use only the TOPMOST Authentication-Results header. It is the one added by
   * the receiving mail system; anything below it travelled with the message and
   * could have been written by the sender. */
  function authResults(headers) {
    var ar = all(headers, 'Authentication-Results');
    if (ar.length) {
      var r = parseAuthResults(ar[0]);
      r.source = 'Authentication-Results';
      return r;
    }
    var rs = one(headers, 'Received-SPF');
    var fallback = { authservId: null, spf: null, dkim: [], dmarc: null, mailfrom: null, headerFrom: null, source: null };
    if (rs) {
      var m = /^\s*([a-z]+)/i.exec(rs);
      fallback.spf = m ? m[1].toLowerCase() : null;
      var e = /envelope-from=\s*"?<?([^\s;">]+)/i.exec(rs);
      if (e) fallback.mailfrom = domainOf(e[1]) || domainOf('@' + e[1]);
      fallback.source = 'Received-SPF';
    }
    return fallback;
  }

  function dkimSummary(list) {
    if (!list.length) return null;
    for (var i = 0; i < list.length; i++) if (list[i].result === 'pass') return 'pass';
    return list[0].result;
  }

  /* ---------------- route ---------------- */

  function isPublicV4(ip) {
    var p = ip.split('.').map(Number);
    if (p.some(function (n) { return n > 255; })) return false;
    var a = p[0], b = p[1];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 172 ? (b >= 16 ? b <= 31 : false) : false) return false;
    if (a === 192 ? b === 168 : false) return false;
    if (a === 169 ? b === 254 : false) return false;
    if (a === 100 ? (b >= 64 ? b <= 127 : false) : false) return false;   // carrier-grade NAT
    return true;
  }

  function publicIPs(text) {
    var found = String(text).match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [];
    return found.filter(function (ip, i) { return isPublicV4(ip) ? found.indexOf(ip) === i : false; });
  }

  function hopTime(v) {
    var s = String(v);
    var semi = s.lastIndexOf(';');
    var cand = semi !== -1 ? s.slice(semi + 1) : null;
    if (!cand) {
      var d2 = /\w{3},\s*\d{1,2}\s+\w{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*[+-]\d{4}/.exec(s);
      cand = d2 ? d2[0] : null;
    }
    if (!cand) return null;
    var t = Date.parse(cand.replace(/\([^)]*\)/g, '').trim());
    return isNaN(t) ? null : t;
  }

  /* Received headers are prepended, so the list is reversed to read oldest first. */
  function route(headers) {
    return all(headers, 'Received').slice().reverse().map(function (r) {
      var f = /\bfrom\s+([^\s;()]+)/i.exec(r);
      var b = /\bby\s+([^\s;()]+)/i.exec(r);
      return { from: f ? f[1] : null, by: b ? b[1] : null, ips: publicIPs(r), time: hopTime(r), raw: r };
    });
  }

  /* ---------------- analysis ---------------- */

  function analyze(raw) {
    var headers = parse(raw);
    if (headers.length < 2) {
      return { ok: false, error: 'That does not look like message headers. Copy the whole header block, starting at Received or Delivered-To.' };
    }

    var auth = authResults(headers);
    var dkimResult = dkimSummary(auth.dkim);

    var fromRaw = one(headers, 'From');
    var from = domainOf(fromRaw);
    var returnPath = domainOf(one(headers, 'Return-Path'));
    var replyTo = domainOf(one(headers, 'Reply-To'));
    var sig = one(headers, 'DKIM-Signature');
    var sigDomain = sig ? ((/\bd=([A-Za-z0-9.-]+)/.exec(sig) || [])[1] || null) : null;
    if (sigDomain) sigDomain = sigDomain.toLowerCase();
    var envelope = auth.mailfrom || returnPath;
    var dkimDomains = auth.dkim.filter(function (d) { return d.result === 'pass'; })
      .map(function (d) { return d.domain; }).filter(Boolean);
    if (!dkimDomains.length ? sigDomain : null) dkimDomains = [sigDomain];

    var bad = [], warn = [], info = [], good = [];

    // --- authentication outcome ---
    if (auth.dmarc === 'fail') {
      bad.push('DMARC failed: the domain that authenticated does not match the address in the From line.');
    } else if (auth.dmarc === 'pass') {
      good.push('DMARC passed: the visible sender domain (' + (from || 'From') + ') is the one that authenticated.');
    } else if (auth.dmarc) {
      warn.push('DMARC result was "' + auth.dmarc + '", so the From address was not verified.');
    } else {
      warn.push('No DMARC result was recorded, so the From address was never verified against the sending domain.');
    }
    if (auth.spf === 'fail') bad.push('SPF failed: the delivering server was not authorised by the sending domain.');
    else if (auth.spf === 'softfail') warn.push('SPF soft-failed: the sending domain does not fully vouch for this server.');
    if (dkimResult === 'fail') {
      if (auth.dmarc === 'pass') info.push('One DKIM signature failed, but another passed and DMARC passed, so the message is still authenticated.');
      else bad.push('DKIM failed: the signature did not validate, so the message may have been altered.');
    }

    // --- domain alignment ---
    /* When DMARC passes, the receiving server has already checked alignment the
     * way the standard defines it. Differing envelope, bounce and signing domains
     * are then normal: newsletters and transactional mail are sent through a
     * provider (Mailchimp, SendGrid, Amazon SES ...) that uses its own bounce
     * domain. Reporting them as warnings flagged legitimate mail as suspicious. */
    var dmarcPassed = auth.dmarc === 'pass';
    if (from) {
      if (envelope ? !aligned(envelope, from) : false) {
        (dmarcPassed ? info : warn).push('The envelope sender (' + envelope + ') is a different domain from the visible From (' + from + ').' +
          (dmarcPassed ? ' Normal when mail is sent through an email provider.' : ''));
      }
      if (dkimDomains.length ? !dkimDomains.some(function (d) { return aligned(d, from); }) : false) {
        (dmarcPassed ? info : warn).push('The DKIM signature is from ' + dkimDomains.join(', ') + ', not ' + from + '.' +
          (dmarcPassed ? ' Normal when mail is sent through an email provider.' : ''));
      }
      if (replyTo ? !aligned(replyTo, from) : false) {
        warn.push('Replies would go to ' + replyTo + ', not ' + from + '. That is a common phishing pattern, though some companies use a separate support domain.');
      }
    } else {
      warn.push('No readable From address was found.');
    }

    // --- verdict ---
    var level, tag, title;
    if (bad.length) { level = 'fail'; tag = 'Failed checks'; title = 'This message did not authenticate'; }
    else if (warn.length > 1) { level = 'warn'; tag = 'Suspicious'; title = 'Several things here do not line up'; }
    else if (warn.length === 1) { level = 'warn'; tag = 'Worth a look'; title = 'Mostly clean, with one thing to check'; }
    else { level = 'pass'; tag = 'Looks genuine'; title = 'Authentication passed and the sender checks out'; }

    var hops = route(headers);
    var origin = null;
    for (var i = 0; i < hops.length; i++) { if (hops[i].ips.length) { origin = hops[i].ips[0]; break; } }
    var transit = null;
    if (hops.length > 1 ? (hops[0].time !== null ? hops[hops.length - 1].time !== null : false) : false) {
      transit = hops[hops.length - 1].time - hops[0].time;
    }

    return {
      ok: true,
      verdict: { level: level, tag: tag, title: title },
      findings: { bad: bad, warn: warn, info: info, good: good },
      auth: {
        spf: auth.spf, dkim: dkimResult, dmarc: auth.dmarc,
        dkimResults: auth.dkim, authservId: auth.authservId, source: auth.source
      },
      domains: {
        from: from, envelope: envelope, returnPath: returnPath, replyTo: replyTo,
        dkim: dkimDomains, orgFrom: orgDomain(from)
      },
      message: {
        from: decodeWords(fromRaw), subject: decodeWords(one(headers, 'Subject')),
        date: one(headers, 'Date'), messageId: one(headers, 'Message-ID'),
        returnPath: one(headers, 'Return-Path')
      },
      route: { hops: hops, originIp: origin, transitMs: transit },
      headers: headers
    };
  }

  return {
    parse: parse,
    decodeWords: decodeWords,
    domainOf: domainOf,
    orgDomain: orgDomain,
    aligned: aligned,
    parseAuthResults: parseAuthResults,
    authResults: authResults,
    publicIPs: publicIPs,
    route: route,
    analyze: analyze
  };
});

/* CLI: node email-auth-headers.js headers.txt   (or pipe headers on stdin) */
if (typeof require === 'function' ? (typeof module === 'object' ? require.main === module : false) : false) {
  (function () {
    var fs = require('fs');
    var file = process.argv[2];
    var raw = file ? fs.readFileSync(file, 'utf8') : fs.readFileSync(0, 'utf8');
    var r = module.exports.analyze(raw);
    if (process.argv.indexOf('--json') !== -1) { console.log(JSON.stringify(r, null, 2)); return; }
    if (!r.ok) { console.error(r.error); process.exitCode = 1; return; }
    console.log(r.verdict.tag.toUpperCase() + ' — ' + r.verdict.title);
    console.log('SPF ' + (r.auth.spf || 'none') + ' · DKIM ' + (r.auth.dkim || 'none') + ' · DMARC ' + (r.auth.dmarc || 'none'));
    ['bad', 'warn', 'info', 'good'].forEach(function (k) {
      r.findings[k].forEach(function (f) { console.log('  [' + k + '] ' + f); });
    });
    if (r.route.originIp) console.log('Origin IP: ' + r.route.originIp + ' (' + r.route.hops.length + ' hops)');
    process.exitCode = r.verdict.level === 'fail' ? 2 : 0;
  })();
}
