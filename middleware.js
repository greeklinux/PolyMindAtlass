// Edge Routing Middleware for the PolyMind Atlas showcase (a static site).
//
// Mirrors the blocking layer used on the main portfolio: a committed IP block
// list, a high-risk-country block list, and a country ALLOWLIST that sits above
// both, all enforced with a 403 at the edge before any asset is served.
// Everything is overridable at runtime with the BLOCK_IPS / BLOCK_COUNTRIES /
// ALLOW_COUNTRIES / OWNER_IP environment variables, so the lists can change
// without a code edit.
//
// Safety: the whole decision is wrapped in try/catch and fails OPEN. If anything
// unexpected happens, the request is allowed through rather than the site going
// dark. Owner traffic (OWNER_IP, or a browser marked once with ?owner=<key>) is
// never blocked.
//
// Trust boundary (2026-09-15 audit). The client address and the country come
// from ipAddress() and geolocation(), which read x-real-ip and
// x-vercel-ip-country: the two headers the platform sets itself. x-forwarded-for
// is deliberately NOT consulted. Its leftmost element is the value a client
// supplies, and reading it let a request forge an address equal to OWNER_IP and
// walk through the country block.
import { next, ipAddress, geolocation } from '@vercel/functions'

// The names those three helpers read. Held here only so a failed helper call
// can fall back to the same header rather than to "allow".
const IP_HEADER = 'x-real-ip'
const COUNTRY_HEADER = 'x-vercel-ip-country'

const STATIC_BLOCKED_IPS = [
  '45.194.70.248', // Ucloud HK datacenter (Bangkok, TH); GreyNoise: malicious known scanner
  '23.111.114.116', // AS39134 Edinaya Set (Moscow, RU); server network, spoofed old-Safari UA
]

const DEFAULT_BLOCKED_COUNTRIES = 'RU,CN,HK,KP,IR,BY,SY,CU,VE'

// Security headers for responses this middleware generates itself. A block page
// is short-circuited before the static routing layer, so it cannot be assumed to
// inherit the header set in vercel.json; it carries its own.
const BLOCK_HEADERS = {
  'content-type': 'text/plain; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy':
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'x-permitted-cross-domain-policies': 'none',
  'x-robots-tag': 'noindex, nofollow',
}

// Separators are deliberately generous. Splitting on the comma alone meant a
// list written "RU;CN", or across a newline, parsed as one meaningless entry
// and left the set empty, which is the same silent failure as the lowercase
// list: the filter reports nothing and blocks nothing.
function toSet(value, transform = (s) => s) {
  return new Set(
    String(value ?? '')
      .split(/[,;\s]+/)
      .map((s) => transform(s.trim()))
      .filter(Boolean),
  )
}

const upper = (s) => s.toUpperCase()

// ONE CANONICAL SPELLING OF A COUNTRY CODE.
//
// trim() removes the characters JavaScript calls whitespace, which is not the
// set of characters that are invisible in a country code. Measured against this
// middleware with the default block list and the allowlist off:
//
//   x-vercel-ip-country: RU            403      the control working
//   x-vercel-ip-country: RU<U+00A0>    403      non-breaking space, trimmed
//   x-vercel-ip-country: RU<U+00AD>    200      SOFT HYPHEN, straight past
//   x-vercel-ip-country: <U+0085>RU    200      NEXT LINE, straight past
//   x-vercel-ip-country: RU<U+200B>    200      ZERO WIDTH SPACE, straight past
//
// U+00AD and U+0085 are single bytes in a header value, so neither needs the
// sender to speak UTF-8. In the other direction, with ALLOW_COUNTRIES=US, 74 of
// 106 generated spellings of "US" were REFUSED, so the same asymmetry was also
// a way to lock a real visitor out.
//
// NFKC folds the compatibility spellings (the fullwidth letters, the
// ideographic space) onto ASCII, every format and control character is removed,
// and what is left has to be exactly two ASCII letters or this returns ''.
// "R<U+00AD>U" canonicalises to "RU" because a soft hyphen between two letters
// is invisible; "RUX" canonicalises to nothing, because the third letter is
// real. The combining grapheme joiner is named rather than reaching for \p{Mn},
// because a diaeresis is not invisible.
const INVISIBLE = /[\p{Cf}\p{Cc}\p{Zs}\p{Zl}\p{Zp}͏᠎]/gu

function canonicalCountry(value) {
  const letters = String(value ?? '').normalize('NFKC').replace(INVISIBLE, '').toUpperCase()
  return /^[A-Z]{2}$/.test(letters) ? letters : ''
}

// Both spellings of a configured entry, never one instead of the other. A list
// pasted out of a chat window can carry a zero width space, and an entry that
// matches no country code is a dashboard field that looks configured and
// enforces nothing. Keeping the raw entry as well means this can only ever add
// a match, never remove one that used to work.
const countrySet = (value) => {
  const out = toSet(value, upper)
  for (const entry of [...out]) {
    const canon = canonicalCountry(entry)
    if (canon) out.add(canon)
  }
  return out
}

// An address is compared in one canonical form on both sides of the comparison.
// Vercel reports a plain IPv4 today, but an IPv4-mapped IPv6 address is the same
// host written differently, and against an exact string match
// "::ffff:45.194.70.248" walked straight past the entry for "45.194.70.248".
function normaliseIp(value) {
  let ip = String(value ?? '').trim().toLowerCase()
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1)
  const mapped = /^(?:::ffff:|::)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip)
  return mapped ? mapped[1] : ip
}

// THE SAME HOST, WRITTEN THE OTHER WAY, IS THE SAME HOST.
//
// normaliseIp lowercases, unwraps brackets and folds the IPv4-mapped form, and
// that left three spellings of one address that an exact string match could not
// see. Measured against this middleware with BLOCK_IPS carrying both entries,
// the exact spellings as the control:
//
//   203.0.113.7                              403  (control)
//   2001:db8::1                              403  (control)
//   203.0.113.7<U+00AD>                      200  soft hyphen
//   203.000.113.007                          200  the same address, padded
//   2001:0db8:0000:0000:0000:0000:0000:0001  200  the same address, expanded
//   2001:db8:0:0:0:0:0:1                     200  the same address, uncompressed
//
// It reads as a block list problem and it is worse as an OWNER_IP problem: an
// owner who writes their own IPv6 address the way their router prints it gets
// no bypass at all, and the failure is silent, which is the shape of escape
// hatch this site has already shipped once.
//
// Everything here is ADDITIVE. The literal entry is always kept, so nothing
// that matched before can stop matching, and a form is only added when it
// parses cleanly. Anything that does not parse gets no extra form and keeps
// exactly today's behaviour.
//
// The IPv4 octets are read as DECIMAL, which is what an operator typing an
// address means. Nothing here accepts the octal or the single-integer spellings
// of an address, because those are ways of writing a DIFFERENT number and
// guessing which one was meant is how a canonicaliser starts colliding hosts.
function canonicalIpv4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  if (!m) return ''
  const octets = m.slice(1).map(Number)
  if (octets.some((n) => n > 255)) return ''
  return octets.join('.')
}

// Fully expanded, eight groups of four lowercase hex digits. Expanding rather
// than compressing is deliberate: expansion has exactly one answer, so two
// different addresses can never land on the same string, while the compressed
// form has rules about WHICH zero run gets elided that are easy to get subtly
// wrong. A zone identifier is refused rather than stripped, because it names a
// link and two hosts on different links are not the same host.
function canonicalIpv6(ip) {
  if (!ip.includes(':') || !/^[0-9a-f:]+$/.test(ip)) return ''
  const halves = ip.split('::')
  if (halves.length > 2) return ''
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const bad = (g) => g === '' || g.length > 4
  if (head.some(bad) || tail.some(bad)) return ''
  let groups
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length
    if (fill < 1) return ''
    groups = [...head, ...Array(fill).fill('0'), ...tail]
  } else {
    if (head.length !== 8) return ''
    groups = head
  }
  return groups.map((g) => g.padStart(4, '0')).join(':')
}

const canonicalIp = (ip) => canonicalIpv4(ip) || canonicalIpv6(ip) || ''

// Every spelling of one value that this file is willing to treat as that value.
// Used to BUILD the sets and to TEST against them, so the two sides cannot
// normalise differently, which is the mistake that started this whole audit.
function ipForms(value) {
  const out = new Set()
  const base = normaliseIp(value)
  if (base) out.add(base)
  const stripped = normaliseIp(String(value ?? '').replace(INVISIBLE, ''))
  if (stripped) out.add(stripped)
  for (const form of [base, stripped]) {
    const canon = form && canonicalIp(form)
    if (canon) out.add(canon)
  }
  return out
}

function inIpSet(set, value) {
  if (!set.size) return false
  for (const form of ipForms(value)) if (set.has(form)) return true
  return false
}

const ipSet = (values) => {
  const out = new Set()
  for (const v of values) for (const form of ipForms(v)) out.add(form)
  return out
}

const BLOCKED_IPS = ipSet([
  ...STATIC_BLOCKED_IPS,
  ...toSet(process.env.BLOCK_IPS),
])
// Country codes are normalised on the way in. A list configured as "ru,cn"
// used to build a set that the uppercased request country could never match,
// which switched the whole country block off without reporting anything.
//
// A configured value that parses to nothing is now treated as a mistake rather
// than as an instruction. An empty string, whitespace, or a list written with
// the wrong separator all left this set empty and disabled the country block
// with no signal anywhere, which is a security filter failing open on malformed
// input. Setting BLOCK_COUNTRIES to "none" switches it off deliberately.
const CONFIGURED_COUNTRIES = countrySet(process.env.BLOCK_COUNTRIES)
// "none" switches the country block off, but only when it is the whole value.
// Membership rather than equality meant one stray token in a real list, as in
// "RU,CN,NONE", emptied the set and disabled every entry beside it. An off
// switch that is also a token is an off switch that fires by accident.
const BLOCKED_COUNTRIES = (CONFIGURED_COUNTRIES.size === 1 && CONFIGURED_COUNTRIES.has('NONE'))
  ? new Set()
  : CONFIGURED_COUNTRIES.size
    ? CONFIGURED_COUNTRIES
    : countrySet(DEFAULT_BLOCKED_COUNTRIES)
// ---------------------------------------------------------------------------
// COUNTRY ALLOWLIST. The sibling portfolio grew one (lib/blocklist.ts,
// isAllowedCountry) and this property had no equivalent, so the same decision
// could not be applied to both sites at once. This is that mechanism, spelled
// the same way, so one value turns both properties.
//
// An allowlist is not a longer blocklist. The two fail in opposite directions:
// a blocklist that has never heard of a country lets it through, an allowlist
// that has never heard of one refuses it. The set below is what is PERMITTED.
//
// ALLOW_COUNTRIES configures it, comma, semicolon or whitespace separated, so
// the decision changes without a deploy. The whole value "ANY" switches the
// allowlist off and leaves the blocklist underneath to run on its own.
//
// SHIPPED OFF, AND THAT IS THE FINDING RATHER THAN AN OVERSIGHT. Turned on, the
// portfolio's copy locked the owner out of the live site within minutes: the
// owner bypass needs either OWNER_IP to match or a browser already carrying the
// owner cookie, and on an ordinary visit from an ordinary address neither was
// true. An escape hatch nobody has walked through is not an escape hatch. Set
// ALLOW_COUNTRIES=US to turn it on once a bypass has actually been used.
const DEFAULT_ALLOW_COUNTRIES = 'ANY'

// Resolve to ONE set, THEN decide once whether it is an off switch.
//
// The portfolio's first spelling applied the "ANY" test only to the override
// path, so the DEFAULT of "ANY" built an allowlist whose single member was the
// literal string ANY. No country code equals "ANY", so the control that was
// meant to be off refused every visitor on earth instead. The off switch has to
// be honoured wherever the value came from, which is why the resolution and the
// off-switch test are two separate steps here rather than one nested ternary.
const RESOLVED_ALLOW = process.env.ALLOW_COUNTRIES === undefined
  ? countrySet(DEFAULT_ALLOW_COUNTRIES)
  // A configured value that parses to nothing is a typo, not an instruction to
  // refuse the entire internet, so it falls back to the default. This is the
  // same rule BLOCK_COUNTRIES follows above, pointed the other way: there,
  // falling back preserves blocking; here, falling back preserves serving.
  : countrySet(process.env.ALLOW_COUNTRIES).size
    ? countrySet(process.env.ALLOW_COUNTRIES)
    : countrySet(DEFAULT_ALLOW_COUNTRIES)

// Tested as the WHOLE value, never by membership. An off switch that is also an
// ordinary token is an off switch that fires by accident: one stray ANY typed
// into a real list would otherwise open the site to everywhere while the
// operator read a populated setting.
const ALLOWED_COUNTRIES = (RESOLVED_ALLOW.size === 1 && RESOLVED_ALLOW.has('ANY'))
  ? new Set()
  : RESOLVED_ALLOW

// Empty means NO allowlist, not "allow nobody".
const COUNTRY_ALLOWLIST_ACTIVE = ALLOWED_COUNTRIES.size > 0

// An UNREADABLE country is refused while the allowlist is active, and that is
// the entire point of having one: the absent case is the case a blocklist waves
// through. platformCountry() yields '' when the platform header is missing or
// when geolocation() throws, and '' is not a member of any allowlist. The owner
// bypass is resolved before this runs, so the owner still gets in when the
// header is missing.
function isAllowedCountry(country) {
  if (!COUNTRY_ALLOWLIST_ACTIVE) return true
  // Both spellings, and the trimmed one FIRST. Adding the canonical test can
  // only ever admit a visitor this used to refuse, never refuse one it used to
  // admit, which is the only direction an allowlist is allowed to move in on a
  // site whose owner has already been locked out of one once.
  if (ALLOWED_COUNTRIES.has(String(country ?? '').trim().toUpperCase())) return true
  const canon = canonicalCountry(country)
  return !!canon && ALLOWED_COUNTRIES.has(canon)
}

// The mirror of isAllowedCountry, and additive for the same reason. An
// UNREADABLE country is NOT blocked: a block list that refused everything it
// could not parse would take the whole site down the first time the platform
// header went missing, which is a far larger outage than the one it prevents.
function isBlockedCountry(country) {
  const code = String(country ?? '').trim().toUpperCase()
  if (code && BLOCKED_COUNTRIES.has(code)) return true
  const canon = canonicalCountry(country)
  return !!canon && BLOCKED_COUNTRIES.has(canon)
}

const OWNER_IPS = ipSet(toSet(process.env.OWNER_IP))

// An address list is an exact match against one canonical form. A CIDR, a
// range, a glob or a port reads as an ordinary entry, matches no request, and
// blocks nothing: the filter reports a list and enforces an empty one. The
// list cannot be widened here without changing what the comparison means, so
// the unusable entries are named in the runtime log instead of disappearing.
// A colon followed by digits is a port only after an IPv4 address; an IPv6
// address ends that way too and is a perfectly good entry.
const UNMATCHABLE = /[/*\-]|^\d{1,3}(?:\.\d{1,3}){3}:\d+$/
for (const [name, set] of [['BLOCK_IPS', BLOCKED_IPS], ['OWNER_IP', OWNER_IPS]]) {
  for (const entry of set) {
    if (UNMATCHABLE.test(entry)) {
      console.warn(
        `middleware: ${name} entry ${JSON.stringify(entry)} is compared as a literal address ` +
        `and matches no request. Ranges, globs and ports are not supported; list each address.`,
      )
    }
  }
}

export const config = {
  // Run on every request except Vercel internals and the three text files that
  // exist to be fetched by anyone, so the block covers every page and asset
  // without paying for it on a favicon.
  //
  // EVERY EXCLUSION IS ANCHORED AND EVERY DOT IS ESCAPED, and neither was true
  // before. The alternatives were matched at one position, right after the
  // leading slash, with no `$`, so each one excluded a PREFIX rather than a
  // path, and an unescaped `.` matched any character. Measured against the
  // matcher as it was, with '/' and '/index.html' as the controls that prove
  // the harness can tell a match from a miss:
  //
  //   /robots.txt/deep/page   EXCLUDED, so the block never ran
  //   /sitemap.xml/deep/page  EXCLUDED
  //   /favicon.icoX           EXCLUDED
  //   /faviconXico            EXCLUDED  (the dot was a wildcard)
  //   /robots0txt             EXCLUDED
  //
  // Nothing is served under those prefixes today, so this is a bypass with
  // nothing behind it rather than a way in: a request that takes it reaches a
  // 404 instead of a 403. It is worth closing anyway, on two grounds. It is a
  // hole whose reachability depends on a file nobody has added yet, which is
  // the kind that gets opened by an unrelated commit. And the sibling
  // portfolio's middleware.ts hit this exact defect, fixed it, and wrote the
  // reasoning down; the same rule spelled two different ways across two
  // deployments is a difference nobody chose.
  //
  // Real requests are unaffected: /favicon.ico, /robots.txt and /sitemap.xml
  // are still excluded, and every other path, including /, /index.html,
  // /og-image.png, /kit/* and /data/*, still runs through the block.
  matcher: '/((?!_vercel/|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$).*)',
}

function forbidden() {
  return new Response('Forbidden', { status: 403, headers: BLOCK_HEADERS })
}

// Compare a caller-supplied value against a secret, over a FIXED width.
//
// TWO SHAPES HAVE BEEN WRONG HERE, and the second one is why this is a digest
// and not another loop.
//
// The first was an early return on `a.length !== b.length`, which answers "is
// your guess the right LENGTH" before comparing anything and answers it much
// faster than a real comparison does. Length is not the secret, but it narrows
// a search and it costs an attacker nothing to collect.
//
// The second was the repair for it: fix the ROUND count from the secret alone
// and fold the length difference into the accumulator. The comment that shipped
// with it claimed the work done "is a function of the secret's length, which is
// the same on every request, and never of what the caller sent". That claim was
// false, and the probe that vouched for it could not see why: it counted LOOP
// ITERATIONS, which really were constant, while the body read
// `i < a.length ? a.charCodeAt(i) : 0`, so the loop only TOUCHED
// min(a.length, rounds) characters of the guess. Counting the character reads
// instead, against a 33 character secret:
//
//   guess length      1    32    33    34   200
//   character reads  34    65    66    67    97
//
// Five distinct amounts of work for five caller-chosen lengths. It is a weaker
// oracle than the early return was, and where the curve stops rising names the
// secret's length outright whenever that length is above the 64 floor.
//
// Hashing both sides first is what actually removes it, which is the
// construction the sibling portfolio's admin route has always used on the Node
// side. Every comparison then runs over exactly 32 bytes whatever arrived, and
// the secret is never read character by character at all, so the only thing the
// work can distinguish is equality, which is the answer this function is
// willing to give anyway. The digest of the guess costs time proportional to
// the guess, which is the caller's own input and is a function of nothing
// secret.
//
// The edge runtime has no SYNCHRONOUS digest, which is what the previous note
// gave as the reason for the loop. It does have crypto.subtle.digest, and both
// call sites are already inside an async handler, so the await costs nothing
// structural. That was the thing worth re-checking rather than inheriting.
//
// `secret` MUST be the secret side. Both call sites pass it that way: the
// derived cookie token, and OWNER_KEY.
//
// The empty-secret guard is load bearing. Two SHA-256 digests of the empty
// string are equal, so without it an unset OWNER_KEY would match an empty guess
// and hand the owner bypass to anyone who asked for it.
async function secretEqualsDigest(given, secret) {
  if (typeof given !== 'string' || typeof secret !== 'string') return false
  if (secret.length === 0) return false
  const enc = new TextEncoder()
  const [ga, gb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(given)),
    crypto.subtle.digest('SHA-256', enc.encode(secret)),
  ])
  const x = new Uint8Array(ga)
  const y = new Uint8Array(gb)
  let diff = 0
  for (let i = 0; i < 32; i += 1) {
    diff |= x[i] ^ y[i]
  }
  return diff === 0
}

// The value written into the pma_owner cookie.
//
// WHAT WAS WRONG. The cookie used to carry the OWNER_KEY itself, url-encoded.
// OWNER_KEY is the admin/bypass credential: it is what the owner types into
// `?owner=<key>`, and it is the same key the sibling portfolio uses on
// /api/gate/admin. Writing it verbatim into a year-long cookie makes the
// browser a durable store of the master secret. HttpOnly stops a page script
// from READING it, but it does not stop the cookie leaking any of the other
// ways a cookie leaks (a shared or synced browser, a backup, a logging proxy
// that records Set-Cookie/Cookie, a sibling-host scope mistake), and any one of
// those disclosures is disclosure of the credential, not merely of one
// browser's bypass. That is the persistence foothold this repository argues
// against: the durable artefact should never be the secret itself.
//
// The fix mirrors the portfolio's lib/guard.ts ownerCookieValue(): the cookie
// carries an HMAC of a fixed label under OWNER_KEY, computed with Web Crypto so
// it runs on the edge. It is still unforgeable (producing it needs the key),
// still marks exactly one browser, and expires the same way, but it is a
// one-way function of the key: a captured cookie reveals nothing about the key
// and opens nothing else. Deriving the key back from it is a brute force of the
// full OWNER_KEY against SHA-256.
//
// WHY THE LABEL IS NOT A CONSTANT: a marked browser had no revocation path.
//
// The cookie lives for a year. HttpOnly keeps a script on the page from reading
// it, and that is the only leak it addresses; a shared or synced browser, a
// profile backup, a proxy that logs the Cookie header, or a laptop that changes
// hands all hand the value over intact, and whoever holds it then has the owner
// bypass (past the country block and the address block) for the rest of that
// year. There is no list of issued marks to delete, because there is no server
// side record of one: the value is a pure function of the key.
//
// So the only way to withdraw a mark was to change OWNER_KEY, and that is not a
// revocation, it is a credential rotation, and of a value this deployment SHARES
// with the sibling portfolio, where the same OWNER_KEY is the ?key= credential
// for /api/gate/admin. Withdrawing one browser's bypass here meant re-keying an
// admin endpoint on another site, which is expensive enough that in practice it
// does not happen and the mark is forever.
//
// OWNER_COOKIE_EPOCH is that lever, and it costs one environment variable. It is
// mixed into the HMAC label, so bumping it (any value: "2", a date, a word)
// makes every previously issued pma_owner cookie stop matching on the next
// request, while OWNER_KEY and the portfolio are untouched. Unset, the label is
// byte for byte what it was, so marked browsers keep working across this change.
const OWNER_COOKIE_LABEL = 'pma_owner:v1'

function ownerCookieLabel() {
  const epoch = String(process.env.OWNER_COOKIE_EPOCH ?? '').trim()
  return epoch ? `${OWNER_COOKIE_LABEL}#${epoch}` : OWNER_COOKIE_LABEL
}

// Keyed by BOTH inputs. Keying it by the key alone meant a changed epoch was
// answered out of the cache with the old cookie value, so the revocation lever
// would have done nothing until the edge instance recycled.
const ownerTokenCache = new Map()
async function ownerCookieToken(ownerKey) {
  const label = ownerCookieLabel()
  const cacheKey = `${label}\u0000${ownerKey}`
  const cached = ownerTokenCache.get(cacheKey)
  if (cached) return cached
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(ownerKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(label))
  const out = [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  ownerTokenCache.set(cacheKey, out)
  return out
}

// A per-instance backstop on `?owner=` guessing, mirroring the portfolio's
// `ownermark` limit (middleware.ts). The comparison is already constant-time
// and a high-entropy key is not brute-forceable over the network, but the query
// path answered an unlimited number of guesses per request with no cost, and a
// wrong guess is a plain block indistinguishable from any other, so nothing
// signalled the grinding. This does not replace a platform rate limit: it is
// per edge instance and resets on a cold start, but it stops one host from
// spending the key at full speed on every page URL. A real owner needs the
// query once per browser.
//
// WHAT BOUNDS THE MAP, since the sweep on its own did not. The scan only ever
// removed entries whose window had already run out, so once more than 5000 keys
// were live at the same time it removed nothing and ran a full pass of the map
// on EVERY request: a structure that grows without limit and charges each later
// request for the growth. Two changes, and neither touches the limit itself.
//
// The scan is time gated, so it happens at most once a second instead of once a
// request, which is enough to keep expired entries from piling up and turns an
// O(n) cost per request back into O(1) amortised.
//
// And there is a hard ceiling. Above it a key that does not already exist is
// simply not created and the request is NOT budgeted. That direction is
// deliberate: a false here means "let the key comparison decide", which is the
// control that actually gates the owner path, while a true would mean a 403 for
// every new address that so much as carries `?owner=` in a link. Refusing real
// visitors to preserve a per instance backstop is the wrong trade, and reaching
// the ceiling at all takes more distinct addresses than the backstop is worth.
const ownerMarkBuckets = new Map()
const OWNER_MARK_WINDOW_MS = 10 * 60 * 1000
const OWNER_MARK_LIMIT = 10
const OWNER_MARK_MAX_KEYS = 20000
let ownerMarkLastSweep = 0
function overOwnerMarkBudget(ip) {
  const key = ip || 'unknown'
  const now = Date.now()
  if (ownerMarkBuckets.size > 5000 && now - ownerMarkLastSweep >= 1000) {
    ownerMarkLastSweep = now
    for (const [k, v] of ownerMarkBuckets) {
      if (now - v.t > OWNER_MARK_WINDOW_MS) ownerMarkBuckets.delete(k)
    }
  }
  const b = ownerMarkBuckets.get(key)
  if (!b || now - b.t > OWNER_MARK_WINDOW_MS) {
    if (!b && ownerMarkBuckets.size >= OWNER_MARK_MAX_KEYS) return false
    ownerMarkBuckets.set(key, { n: 1, t: now })
    return false
  }
  b.n += 1
  return b.n > OWNER_MARK_LIMIT
}

function cookieValue(header, name) {
  for (const part of String(header ?? '').split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    if (part.slice(0, eq).trim() !== name) continue
    const raw = part.slice(eq + 1).trim()
    try {
      return decodeURIComponent(raw)
    } catch {
      return raw
    }
  }
  return ''
}

// The two platform values the decision needs, each read behind its own guard.
//
// This is not defensive padding. geolocation() percent-decodes the CITY header,
// a field this file never uses, and decodeURIComponent throws on a malformed
// escape. Inside one try/catch around the whole decision, that throw is not an
// error, it is an ALLOW: a request carrying "x-vercel-ip-city: %" walked past
// the country block and the address block together, from any country, with no
// signal anywhere. The same shape as the malformed-list defect above, reached
// from a field nobody was looking at. A read that fails now yields an empty
// value and the decision continues on the value that did read.
function platformCountry(request) {
  try {
    return String(geolocation(request).country ?? '').trim().toUpperCase()
  } catch {
    try { return String(request.headers.get(COUNTRY_HEADER) ?? '').trim().toUpperCase() } catch { return '' }
  }
}

function platformIp(request) {
  try {
    return normaliseIp(ipAddress(request))
  } catch {
    try { return normaliseIp(request.headers.get(IP_HEADER)) } catch { return '' }
  }
}

export default async function middleware(request) {
  // HOISTED ON PURPOSE, so the catch at the bottom can still act on what was
  // read before a throw rather than on nothing at all. See the note there.
  let ip = ''
  try {
    const url = new URL(request.url)
    // Platform-set values only. See the trust-boundary note at the top.
    ip = platformIp(request)
    const country = platformCountry(request)

    // Let the owner mark this browser once with ?owner=<OWNER_KEY>; sets a cookie
    // so their own visits are never blocked, even from a blocked country/VPN.
    //
    // The cookie carries an HMAC of the key (see ownerCookieToken), never the
    // key itself. The first marker was the literal "pma_owner=1", which anyone
    // could set to walk through the block; the second carried the key verbatim,
    // which turned the browser into a durable store of the master secret. This
    // one is unforgeable without the key and discloses nothing if it leaks.
    // HttpOnly stops a script on the page from reading a cookie; it has never
    // stopped a client from sending one, which is why the value has to be safe
    // to hand out in the first place.
    const ownerKey = process.env.OWNER_KEY || ''
    const givenOwner = url.searchParams.get('owner')
    // Recognise an owner who is ALREADY marked before spending anything from the
    // guess budget.
    //
    // The budget is keyed on the client address and a `?owner=` request that is
    // over it is answered with a 403, not merely refused the mark. Both of those
    // are right, and together they meant that anyone sharing an egress address
    // with the owner, which is what a corporate NAT or a carrier CGNAT is, could
    // spend the ten guesses and then the owner's own marked browser was blocked
    // on any URL that happened to carry the parameter. The budget exists to stop
    // a stranger grinding the key; someone who already holds the derived cookie,
    // or who is coming from OWNER_IP, is not that stranger and has nothing left
    // to guess.
    //
    // The cookie read gets its own guard for the same reason platformCountry and
    // platformIp have theirs: a header read that throws must yield an empty
    // value rather than escape to the outer catch, which is an allow.
    let ownerCookie = ''
    try {
      ownerCookie = cookieValue(request.headers.get('cookie'), 'pma_owner')
    } catch {
      ownerCookie = ''
    }
    const knownOwner =
      (!!ownerKey &&
        (await secretEqualsDigest(ownerCookie, await ownerCookieToken(ownerKey)))) ||
      !!(ip && inIpSet(OWNER_IPS, ip))
    // AN EXHAUSTED BUDGET REFUSES THE MARK, NEVER THE PAGE, and an EMPTY value
    // is not a guess.
    //
    // The budget is the right control and the ordering is the right ordering: a
    // guess has to be rationed BEFORE it is evaluated, or the rationing does
    // nothing. What was wrong is what an exhausted budget did. It answered 403,
    // and the test for "is this an attempt" was `givenOwner !== null`, so the
    // bare parameter with no value counted. Three facts then composed into a
    // denial of the one person this file exists to let through:
    //
    //   1. the budget is keyed on the requester's address (overOwnerMarkBudget);
    //   2. `?owner=` with an EMPTY value spent from it, so no key was needed;
    //   3. config.matcher covers every path, so `/og-image.png?owner=` counted,
    //      and a sub-resource request counts.
    //
    // So eleven `<img src="https://<this host>/og-image.png?owner=">` on any
    // third-party page the owner loads spent the OWNER'S OWN bucket, from the
    // owner's own address, and the owner's next `?owner=<OWNER_KEY>` was met
    // with a 403. Measured against this handler before the change, with the
    // same key from an untouched address as the control:
    //
    //   A1 eleven "?owner=" with an EMPTY value   [200 x10, 403]
    //   A2 owner then presents the CORRECT key    status=403 set-cookie=null
    //   A3 CONTROL same key, untouched address    status=200 set-cookie=present
    //   B1 eleven image loads carrying "?owner="  [200 x10, 403]
    //   B2 owner then presents the CORRECT key    status=403 set-cookie=null
    //
    // It bites exactly when the owner is not yet marked and not on OWNER_IP:
    // every new browser, device or profile, and every browser after an
    // OWNER_COOKIE_EPOCH bump, which is the one moment that revocation lever is
    // ever used. It is also the precondition for turning ALLOW_COUNTRIES on.
    //
    // TWO CHANGES, AND NEITHER TOUCHES THE RATIONING.
    //
    // An empty value can never equal a non-empty key, so counting it as a guess
    // only ever drained the bucket for free. It is now not an attempt at all.
    //
    // And over budget now means the mark is not offered, not that the page is
    // refused: the request carries on as an ordinary visit. A stranger's
    // eleventh guess is still never evaluated, which is the whole of what the
    // budget was for, and the owner who shares an egress address with them
    // still gets the site, still gets every page, and can mark the browser once
    // the window rolls. A control that refuses the owner the site in order to
    // ration a guess has the trade backwards.
    //
    // It closes a small oracle as a side effect. The 403 only ever appeared
    // when OWNER_KEY was set, so twelve unauthenticated `?owner=junk` requests
    // from one address answered "is there a bypass worth grinding here":
    //   OWNER_KEY set    [200 x10, 403, 403]
    //   OWNER_KEY unset  [200 x12]
    // Over budget is now indistinguishable from an ordinary visit.
    const ownerAttempt = !!ownerKey && !!givenOwner
    const mayEvaluateOwnerKey =
      ownerAttempt && (knownOwner || !overOwnerMarkBudget(ip))
    if (mayEvaluateOwnerKey && (await secretEqualsDigest(givenOwner, ownerKey))) {
      const res = next()
      res.headers.append(
        'set-cookie',
        `pma_owner=${await ownerCookieToken(ownerKey)}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`,
      )
      return res
    }
    if (knownOwner) return next()

    // The allowlist is checked FIRST of the two country filters, because it is
    // the stricter one and because refusing an unreadable country is the whole
    // reason to run an allowlist at all. Both sit BELOW the owner bypass above,
    // so the owner is never country-filtered, travelling or on a VPN.
    if (!isAllowedCountry(country)) return forbidden()

    // The blocklist stays underneath as the second layer. It is redundant while
    // the allowlist is active and costs nothing; it is what still stands when
    // the allowlist is switched off with ALLOW_COUNTRIES=ANY, which is how this
    // ships.
    if ((ip && inIpSet(BLOCKED_IPS, ip)) || isBlockedCountry(country)) {
      return forbidden()
    }
  } catch {
    // FAIL OPEN, BUT NOT BLIND.
    //
    // Taking the site down over a middleware error is the wrong trade for a
    // static page, and that has not changed. What has is how much this arm
    // gives away when it is reached. It is the single highest-leverage line in
    // this file: one throw anywhere above it and the committed address
    // blocklist, the country allowlist and the country blocklist all stop
    // applying to that request, at once, with nothing said anywhere.
    //
    // The file already treats that as the hazard it is. platformCountry,
    // platformIp and the cookie read each carry their own guard, and the note
    // above platformCountry spells out why: geolocation() percent-decodes a
    // city header this file never reads, decodeURIComponent throws on a
    // malformed escape, and inside one try around the whole decision that
    // throw is not an error, it is an ALLOW. Three known escapes were closed
    // one at a time. This arm is what is left for the fourth.
    //
    // So the last resort keeps the one check that needs nothing from the
    // request to evaluate. BLOCKED_IPS is a Set built at module scope, `ip`
    // was read through a guard that answers '' rather than throwing, and
    // Set.has does not throw. If the address was read before the failure, a
    // committed address block still holds.
    //
    // DELIBERATELY ONLY THE ADDRESS BLOCKLIST. The country filters are not
    // re-run here, and that is the difference between a backstop and a
    // lockout. An allowlist refuses an unreadable country by design, so
    // applying it in an arm reached BECAUSE something could not be read would
    // turn any unexpected error into a 403 for every visitor on earth,
    // including the owner. The blocklist is a finite list of addresses the
    // owner put there on purpose, so applying it costs a real visitor nothing
    // and costs the owner nothing: their own address is not on it, and the
    // owner bypass is resolved above this line in the normal path.
    //
    // If the throw happened before the address was read, `ip` is still '' and
    // this behaves exactly as it did before: allow. No request that used to be
    // served is refused by this.
    try {
      if (ip && inIpSet(BLOCKED_IPS, ip)) return forbidden()
    } catch {
      // The last resort must not itself be a throw that escapes.
    }
    return next()
  }
  return next()
}
