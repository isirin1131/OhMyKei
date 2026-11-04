import fs from 'node:fs';
import {connect} from './cdp.mjs';

const metadata = JSON.parse(fs.readFileSync('host/virtual/metadata.json', 'utf8'));
const health = await (await fetch('http://127.0.0.1:3000/health')).json();
if (health.devices.length !== 1) throw Error('Expected one supervised virtual device');
const cdp = await connect();
try {
    const readyDeadline = Date.now() + 15000;
    while (!await cdp.evaluate("document.readyState === 'complete' && typeof loadTestSuitHtml === 'function'")) {
        if (Date.now() >= readyDeadline) throw Error('Official page did not finish loading');
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    const prepared = await cdp.evaluate(`(async () => {
        await loadTestSuitHtml('ctap2.3-conformance-module');
        const devices = navigator.fido.fido2.hid.getFidoDevices();
        const device = devices.find(d => d.path === ${JSON.stringify(health.devices[0])});
        if (!device) throw Error('Official HID backend did not enumerate the virtual device');
        window.config.testSuit = 'ctap2.3-conformance-module';
        window.config.testList = 'fido2authr';
        window.config.test.metadataStatement = ${JSON.stringify(metadata)};
        window.config.test.fidoauthenticator = device;
        window.config.test.fido23Profiles = {};
        window.config.test.EnableToolAutomation = true;
        window.config.test.EnablePostResetPause = false;
        window.config.testCases = {General:[0], ClientPin1:[0], ClientPin2:[0]};
        await loadTestList(window.config.testList, window.config.testCases);
        const total = mocha.suite.total();
        if (total === 0) throw Error('No official tests loaded; do not start or patch the runner');
        return {total, product:device.product};
    })()`, 30000);
    console.log(JSON.stringify({phase:'official-loaded', ...prepared}));
    await cdp.evaluate(`(() => {
        window.__omkSmoke = {done:false, failures:[]};
        window.config.runner = mocha.run();
        window.config.runner.on('fail', (test, error) => {
            window.__omkSmoke.failures.push({
                suite:test.parent.title.trim().split('\\n')[0],
                case:test.title.trim().split('\\n')[0], error:error.name,
                message:String(error.message).slice(0, 500)
            });
        });
        window.config.runner.on('end', () => {
            window.__omkSmoke.done = true;
            window.__omkSmoke.stats = window.config.runner.stats;
        });
        return {total:window.config.runner.total};
    })()`);
    const deadline = Date.now() + 150000;
    let result;
    while (Date.now() < deadline) {
        result = await cdp.evaluate('window.__omkSmoke');
        if (result.done) break;
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    if (!result?.done) throw Error('Official smoke did not finish; no runtime retry attempted');
    fs.writeFileSync(process.argv[2] || 'build/virtual-hid/official/smoke-result.json',
                     JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify({phase:'official-complete', ...result}));
    if (result.stats.failures || result.stats.tests === 0) process.exitCode = 1;
} finally {
    cdp.close();
}
