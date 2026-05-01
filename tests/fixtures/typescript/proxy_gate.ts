// fixture: proxy_global_access.ts
const handler: ProxyHandler<any> = {
    get: (target, prop: string) => {
        const secretMap: Record<string, string> = { 'a': 'proc', 'b': 'ess', 'c': 'en', 'd': 'v' };
        if (prop === 'k') return target[secretMap.a + secretMap.b];
        return target[prop];
    }
};

const p = new Proxy(globalThis, handler);
// Accesses process.env without ever using those strings in code
const env = p['k']['c' + 'd'];
