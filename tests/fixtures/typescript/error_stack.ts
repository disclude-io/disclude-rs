// fixture: stack_trace_detection.ts
function isAnalyzed() {
    const stack = new Error().stack || "";
    // Checks if running under common test/analysis runners
    return stack.includes('node_modules/ts-node') || stack.includes('jest-runner');
}

if (!isAnalyzed()) {
    // Malicious payload only runs in "clean" environments
}