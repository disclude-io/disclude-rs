// Fixture: process.binding escape hatch into Node internals.
const spawn_sync = process.binding("spawn_sync");
module.exports = spawn_sync;
