// fixture: tagged_template_deobfuscator.ts
function r(strings: TemplateStringsArray, ...values: any[]) {
    return strings.map(s => s.split('').reverse().join('')).join('');
}

// "mc.revres-larrefe/moc.evil.ppa" -> "app.live.com/referral-server.cm"
const url = r`mc.revres-larrefe/moc.evil.ppa`;
// The analyzer must evaluate the tag function to see the true C2 URL.
