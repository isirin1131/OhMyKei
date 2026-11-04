// Minimal CDP client for the isolated official tool, without UI input injection.
import {pathToFileURL} from 'node:url';
export async function connect() {
    const pages = await (await fetch('http://127.0.0.1:9222/json/list')).json();
    const page = pages.find(p => p.type === 'page');
    if (!page) throw Error('Official tool has no page');
    const socket = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, {once: true});
        socket.addEventListener('error', reject, {once: true});
    });
    let sequence = 0;
    const pending = new Map();
    socket.addEventListener('message', event => {
        const response = JSON.parse(event.data);
        const call = pending.get(response.id);
        if (!call) return;
        pending.delete(response.id);
        clearTimeout(call.timer);
        if (response.error || response.result?.exceptionDetails)
            call.reject(Error(JSON.stringify(response.error || response.result.exceptionDetails)));
        else call.resolve(response.result.result?.value);
    });
    return {
        evaluate(expression, timeout = 15000) {
            const id = ++sequence;
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    pending.delete(id);
                    reject(Error('CDP evaluation timed out'));
                }, timeout);
                pending.set(id, {resolve, reject, timer});
                socket.send(JSON.stringify({id, method: 'Runtime.evaluate', params: {
                    expression, awaitPromise: true, returnByValue: true,
                }}));
            });
        },
        close() { socket.close(); },
    };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.argv[2]) {
    const cdp = await connect();
    try { console.log(JSON.stringify(await cdp.evaluate(process.argv[2]))); }
    finally { cdp.close(); }
}
