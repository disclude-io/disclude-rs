// fixture: intl_data_stash.ts
//
// The Intl APIs accept many free-form string fields — `timeZone`,
// `calendar`, `numberingSystem`, locale identifiers with `-u-` / `-x-`
// extensions. An attacker can stash a payload in any of those fields:
// the call still "looks like i18n" to a reviewer, but the argument
// carries the real cargo. Static analysis should surface the payload
// regardless of which API wraps it — the shape of the string is what
// matters, not the receiver.

// Base64 blob masquerading as a `timeZone` identifier. Decodes to
// "https://evil.app.live.com/referral-server.cm".
const data = new Intl.DateTimeFormat('en-US', {
    hour: 'numeric',
    timeZone: 'aHR0cHM6Ly9ldmlsLmFwcC5saXZlLmNvbS9yZWZlcnJhbC1zZXJ2ZXIuY20=',
}).format(new Date());

// Hex-escape soup hidden in the locale argument — every byte of the
// "locale" is a \xNN escape so the string never resembles a real
// language tag in source.
const stealthBytes = new Intl.NumberFormat(
    '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x61\x70\x70\x2e\x6c\x69\x76\x65\x2e\x63\x6f\x6d',
).format(12345);
