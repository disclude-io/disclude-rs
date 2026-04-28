// Fixture: surrogate pair escape sequences that decode to invisible tag chars.
// \uDB40\uDC41 = U+E0041 TAG LATIN CAPITAL LETTER A (invisible).
const hidden = "\uDB40\uDC41";
module.exports = hidden;
