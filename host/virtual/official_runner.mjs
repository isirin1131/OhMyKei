import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {connect} from './cdp.mjs';

// Official cases may share the same first line (notably BioEnrollment).
export function identity(test) {
    const suitePath=[];
    for (let s=test.parent;s && s.parent;s=s.parent) suitePath.unshift(s.title.trim().split('\n')[0].trim());
    const name=test.title.trim().split('\n')[0].trim();
    return {id:test.fullTitle(),label:[...suitePath,name].join(' / '),suitePath,case:name,type:test.type};
}

// A run can finish without executing every selected test (e.g. a failed hook).
export function assess(result) {
    const tests = result.results.filter(t => t.type === 'test');
    const ids = tests.map(t => t.id);
    const expected = new Set(result.selection.tests.map(t => t.id));
    const missing = [...expected].filter(id => !ids.includes(id));
    const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
    const unexpected = ids.filter(id => !expected.has(id));
    const requiredNotPassed = result.selection.required.filter(id =>
        !tests.some(t => t.id === id && t.status === 'pass'));
    const counts = Object.fromEntries(['pass', 'pending', 'fail'].map(status =>
        [status, result.results.filter(t => t.status === status).length]));
    let outcome = 'passed';
    if (!result.done || missing.length || duplicates.length || unexpected.length || result.infrastructureError)
        outcome = 'incomplete';
    else if (counts.fail) outcome = 'failed';
    else if (!counts.pass || requiredNotPassed.length) outcome = 'inconclusive';
    return {outcome, exitCode:outcome === 'passed' ? 0 : outcome === 'failed' ? 1 : 2,
        counts, missing, duplicates, unexpected, requiredNotPassed};
}

async function main() {
    const [report, configJSON] = process.argv.slice(2);
    const options = JSON.parse(configJSON);
    const metadata = JSON.parse(fs.readFileSync('host/virtual/metadata.json', 'utf8'));
    const state = {done:false, started:new Date().toISOString(), results:[], retries:[], current:null,
        selection:{tests:[],required:[]}, environment:JSON.parse(fs.readFileSync(options.environment, 'utf8'))};
    let cdp;
    let phase = 'connect';
    const save = () => {
        state.assessment = assess(state);
        fs.writeFileSync(report + '.pending', JSON.stringify(state, null, 2) + '\n');
        fs.renameSync(report + '.pending', report);
    };
    try {
        save();
        if (options.grep) new RegExp(options.grep);
        const health = await (await fetch('http://127.0.0.1:3000/health',
            {signal:AbortSignal.timeout(5000)})).json();
        if (health.devices.length !== 1) throw Error('Expected one supervised virtual device');
        cdp = await connect();
        const readyDeadline = performance.now() + 15000;
        while (!await cdp.evaluate("document.readyState === 'complete' && typeof loadTestSuitHtml === 'function'")) {
            if (performance.now() >= readyDeadline) throw Error('Official page did not finish loading');
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        phase = 'select';
        state.selection = await cdp.evaluate(`(async () => {
            await loadTestSuitHtml('ctap2.3-conformance-module');
            const options = ${JSON.stringify(options)};
            const device = navigator.fido.fido2.hid.getFidoDevices().find(d => d.path === ${JSON.stringify(health.devices[0])});
            if (!device) throw Error('Supervised virtual device not enumerated');
            window.config.testSuit = 'ctap2.3-conformance-module';
            window.config.testList = 'fido2authr';
            Object.assign(window.config.test, {metadataStatement:${JSON.stringify(metadata)},
                fidoauthenticator:device, fido23Profiles:{}, EnableToolAutomation:true, EnablePostResetPause:false});
            const groups = window.config.manifesto.testLists.fido2authr.tests;
            const names = options.groups.length ? options.groups : Object.keys(groups);
            if (names.some(name => !groups[name])) throw Error('Unknown official group');
            window.config.testCases = options.suite === 'smoke'
                ? {General:[0],ClientPin1:[0],ClientPin2:[0]}
                : Object.fromEntries(names.map(name => [name,groups[name].cases.map((_,i)=>i)]));
            const files = Object.entries(window.config.testCases).flatMap(([name,indices]) =>
                indices.map(i=>groups[name].cases[i]));
            await loadTestList('fido2authr', window.config.testCases);
            const identity = ${identity.toString()};
            const pattern=options.grep ? new RegExp(options.grep) : null;
            const tests=[];
            mocha.suite.eachTest(test => {if (!pattern || pattern.test(test.fullTitle())) tests.push(identity(test));});
            if (!tests.length) throw Error('No matching tests; runner was not started');
            if (new Set(tests.map(t=>t.id)).size !== tests.length) throw Error('Duplicate test identities; human restart required');
            if (pattern) mocha.grep(pattern);
            let required=['Authr-Generic-1 / P-1','Authr-Generic-1 / P-2','Authr-Generic-1 / P-3',
                'Authr-ClientPin1-GetKeyAgreement / P-1','Authr-ClientPin2-GetKeyAgreement / P-1'];
            if (options.groups.length || options.grep) required=required.filter(label=>tests.some(t=>t.label===label));
            required=required.map(label=>tests.find(t=>t.label===label)?.id || label);
            const diagnostic = error => {
                const message=String(error.message);
                const info={error:error.name,
                    statusCodes:[...new Set(message.match(/(?:CTAP[12]?|HID|U2F)_ERR_[A-Z_0-9]+/g)||[])],
                    category:/timeout|timed out/i.test(message) ? 'timeout' :
                        /Authenticator succeeded when/.test(message) ? 'unexpected-success' : 'assertion-or-error',
                    stackLocations:(String(error.stack).match(/(?:<anonymous>|[\\w.-]+\\.js):[0-9]+:[0-9]+/g)||[]).slice(0,8)};
                // Status-sized numbers are safe; never save assertion payloads or raw messages.
                for (const key of ['actual','expected'])
                    if(Number.isInteger(error[key]) && error[key]>=0 && error[key]<=255) info[key]=error[key];
                return info;
            };
            window.__omkOfficial={done:false,results:[],retries:[],current:null};
            window.__omkObserve=runner=>{
                for(const event of ['test','hook']) runner.on(event,t=>{window.__omkOfficial.current=identity(t);});
                for(const status of ['pass','pending','fail']) runner.on(status,(test,error)=>{
                    window.__omkOfficial.results.push({...identity(test),status,duration:test.duration,
                        attempts:test.currentRetry()+1,
                        ...(status==='pending'?{skipReason:'Official skip; reason not exposed by Mocha'}:{}),
                        ...(error?diagnostic(error):{})});
                });
                runner.on('retry',(test,error)=>window.__omkOfficial.retries.push({
                    ...identity(test),attempt:test.currentRetry()+1,...diagnostic(error)}));
                runner.on('end',()=>{window.__omkOfficial.done=true;window.__omkOfficial.current=null;});
            };
            return {suite:options.suite,groups:Object.keys(window.config.testCases),grep:options.grep,files,tests,required};
        })()`, 30000);
        phase = 'run';
        save();
        const started = await cdp.evaluate(`(() => {
            window.config.runner=mocha.run();
            window.__omkObserve(window.config.runner);
            return {total:window.config.runner.total};
        })()`);
        if (started.total !== state.selection.tests.length) throw Error('Runner selection mismatch; no retry attempted');
        console.log(JSON.stringify({phase:'loaded',total:started.total,groups:state.selection.groups}));
        const deadline=performance.now()+options.timeout*1000;
        let lastProgress=0;
        while (true) {
            const snapshot=await cdp.evaluate('JSON.parse(JSON.stringify({...window.__omkOfficial,stats:window.config.runner.stats}))');
            Object.assign(state,snapshot);
            save();
            if (state.done || performance.now()-lastProgress>=15000) {
                console.log(JSON.stringify({phase:state.done?'complete':'progress',stats:state.stats,
                    retries:state.retries.length,current:state.current?.label,assessment:state.done?state.assessment:undefined}));
                lastProgress=performance.now();
            }
            if (state.done) break;
            if (performance.now()>=deadline) throw Error('Official run deadline reached');
            await new Promise(resolve=>setTimeout(resolve,1000));
        }
    } catch (error) {
        // CDP or transport exceptions may contain payloads. Persist only class and phase.
        state.infrastructureError={phase,error:error.name};
        console.error(JSON.stringify({phase,error:error.name,report}));
    } finally {
        cdp?.close();
        state.finished=new Date().toISOString();
        save();
        process.exitCode=state.assessment.exitCode;
    }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
