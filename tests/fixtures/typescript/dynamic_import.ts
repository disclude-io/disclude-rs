// fixture: dynamic_data_uri_import.ts
async function loadStage2(payload: string) {
    const encoded = Buffer.from(payload).toString('base64');
    const moduleSpecifier = `data:text/javascript;base64,${encoded}`;
    // This bypasses static file-path analysis
    await import(moduleSpecifier);
}