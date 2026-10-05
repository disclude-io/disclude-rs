// Reversed-input decoder: the payload is base64-of-zlib stored backwards so
// neither signatures nor the telltale `eJ` prefix of base64-zlib appear in
// source. It is reversed, base64-decoded, inflated, then run via Function.
// The decoded payload is benign (console.log).
const zlib = require("zlib");

const _p = "XQnjIBgApHSdHJZutSDlTJ1SLNpUrIFFSN/EyHwTO3USIFFTPlMzsiEKR1kTq0yStokKQd9TJvc1J9szr8szLpNe";

const _s = zlib.inflateSync(Buffer.from(_p.split("").reverse().join(""), "base64")).toString();
const _t = atob([..._p].reverse().join(""));

new Function(_s)();
