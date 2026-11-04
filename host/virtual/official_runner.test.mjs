import test from 'node:test';
import assert from 'node:assert/strict';
import {assess, identity} from './official_runner.mjs';

const run = results => ({done:true,results,selection:{tests:[{id:'required'},{id:'optional'}],required:['required']}});
const item = (id,status,type='test') => ({id,status,type});

test('official cases sharing their first title line remain distinct',()=>{
    const parent={title:'BioEnrollment',parent:{parent:null}};
    const first={parent,title:'P-1\nRead sensor information',type:'test',fullTitle(){return parent.title+' '+this.title;}};
    const second={...first,title:'P-1\nEnroll a fingerprint'};
    assert.equal(identity(first).label,identity(second).label);
    assert.notEqual(identity(first).id,identity(second).id);
});

test('required pass plus optional skip succeeds',()=>{
    assert.equal(assess(run([item('required','pass'),item('optional','pending')])).exitCode,0);
});
test('all skipped and skipped required cases cannot turn green',()=>{
    for(const status of ['pending','pass']) {
        const result=assess(run([item('required','pending'),item('optional',status)]));
        assert.equal(result.outcome,'inconclusive');
        assert.equal(result.exitCode,2);
    }
});
test('missing, duplicate, unexpected and unfinished results are incomplete',()=>{
    const valid=[item('required','pass'),item('optional','pass')];
    for(const result of [run(valid.slice(0,1)),run([...valid,valid[0]]),
        run([...valid,item('extra','pass')]),{...run(valid),done:false}])
        assert.equal(assess(result).outcome,'incomplete');
});
test('a protocol failure returns 1',()=>{
    assert.equal(assess(run([item('required','fail'),item('optional','pass')])).exitCode,1);
});
test('hook failures do not impersonate completed tests',()=>{
    assert.equal(assess(run([item('required','fail','hook')])).outcome,'incomplete');
});
test('transport failure cannot turn a partial report green',()=>{
    const result=run([item('required','pass'),item('optional','pass')]);
    result.infrastructureError={phase:'run',error:'Error'};
    assert.equal(assess(result).exitCode,2);
});
