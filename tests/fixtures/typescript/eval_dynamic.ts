// Fixture: eval + Function + dynamic import with non-literal arguments.
export function run(payload: string, name: string): unknown {
    eval(payload);

    const g = new Function(payload + "()");

    return import(`pkg-${name}`);
}
