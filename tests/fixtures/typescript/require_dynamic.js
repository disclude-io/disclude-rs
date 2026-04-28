// Fixture: require() with a non-literal specifier + setTimeout string form.
function load(name) {
    const mod = require(name);
    setTimeout("work()", 10);
    return mod;
}

module.exports = { load };
