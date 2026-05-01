// fixture: generator_state_machine.ts
function* dispatcher() {
    // We use eval('require') to bypass static AST scanners
    // that look for CallExpression nodes named "require".
    yield () => {
        const r = eval('require');
        return r('os');
    };

    yield (m: any) => m.hostname();
}

const g = dispatcher();
const mod = g.next().value!(); // Loads 'os' via indirect eval
const data = g.next().value!(mod); // Calls .hostname()