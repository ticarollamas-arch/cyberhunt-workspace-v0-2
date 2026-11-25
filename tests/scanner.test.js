import {test} from 'node:test';import assert from 'node:assert/strict';import {scan} from '../scanner.js';
test('empty',()=>assert.deepEqual(scan(''),[]));test('html review',()=>assert.equal(scan('x.innerHTML = y')[0].id,'CWE-79'));test('line numbers',()=>assert.equal(scan('\nstrcpy(a,b)')[0].line,2));test('safe example',()=>assert.deepEqual(scan('x.textContent = y'),[]));
