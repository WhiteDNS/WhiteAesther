import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const path = new URL('../src-tauri/assets/worker.js', import.meta.url);
const source = fs.readFileSync(path, 'utf8').replace(/^import .*$/m, '').replace('export default', 'const worker =');
const context = vm.createContext({ TextDecoder, TextEncoder, Uint8Array, DataView, Blob, atob });
vm.runInContext(source, context);
const uuid = '12345678-1234-4234-8234-123456789abc';
function header(host, command = 1) {
    const domain = new TextEncoder().encode(host);
    const bytes = new Uint8Array(23 + domain.length);
    bytes.set(Buffer.from(uuid.replaceAll('-', ''), 'hex'), 1);
    bytes.set([command, 1, 187, 2, domain.length], 18);
    bytes.set(domain, 23);
    return bytes.buffer;
}
context.userId = uuid;
for (const host of ['localhost', 'metadata.google.internal', '127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '172.16.0.1', '100.64.0.1', '::1', '::ffff:127.0.0.1']) {
    context.packet = header(host);
    assert.equal(vm.runInContext('parseVHeader(packet, userId).hasError', context), true, host);
}
context.packet = header('example.com');
assert.equal(vm.runInContext('parseVHeader(packet, userId).addressRemote', context), 'example.com');
assert.equal(vm.runInContext('parseVHeader(packet, userId).portRemote', context), 443);
assert.equal(vm.runInContext('parseVHeader(packet.slice(0, 24), userId).incomplete', context), true);
assert.equal(vm.runInContext('parseVHeader(packet, "00000000-0000-0000-0000-000000000000").hasError', context), true);
context.packet = header('example.com', 2);
assert.equal(vm.runInContext('parseVHeader(packet, userId).hasError', context), true);
for (const host of ['1.1.1.1', '2606:4700:4700::1111', 'www.cloudflare.com']) {
    context.host = host;
    assert.equal(vm.runInContext('publicDestination(host)', context), true, host);
}
assert.ok(!source.includes('bpb.yousef'));
assert.ok(!source.includes('YnBiLnlvdXNlZi'));
console.log('Worker parser: public destinations accepted; private destinations, UDP and invalid identities refused.');

for (const failure of ['connect', 'write', 'read', 'empty']) {
    let calls = 0;
    const sent = [];
    context.connect = () => {
        calls++;
        const first = calls === 1;
        if (first && failure === 'connect') throw new Error('direct blocked');
        return {
            closed: new Promise(() => {}),
            close() {},
            writable: { getWriter: () => ({
                async write() { if (first && failure === 'write') throw new Error('direct write blocked'); },
                releaseLock() {},
            }) },
            readable: { async pipeTo(sink) {
                if (first && failure === 'read') throw new Error('direct read blocked');
                if (first && failure === 'empty') return;
                await sink.getWriter().write(new Uint8Array([42]));
            } },
        };
    };
    context.WritableStream = WritableStream;
    context.remote = { value: null };
    context.socket = { readyState: 1, send(value) { sent.push(value); }, close() { this.readyState = 3; } };
    await vm.runInContext('handleTCPOutBound(remote, "www.cloudflare.com", 443, new Uint8Array([1]), socket, new Uint8Array([0,0]), {pips:["relay.example.com:443"]})', context);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls, 2, `${failure}: relay attempted`);
    assert.equal(sent.length, 1, `${failure}: response returned through relay`);
}
console.log('Worker relay: connect, write, read and empty-response failures recover through the configured relay.');

// Without a user relay, and after a failing one, Cloudflare-hosted targets go through NAT64.
for (const pips of [[], ['relay.example.com:443']]) {
    const dialed = [];
    const sent = [];
    context.fetch = async () => ({ json: async () => ({ Answer: [{ type: 5, data: 'x.example.' }, { type: 1, data: '104.16.124.96' }] }) });
    context.connect = ({ hostname }) => {
        dialed.push(hostname);
        if (!hostname.startsWith('[2')) throw new Error('blocked');
        return {
            closed: new Promise(() => {}),
            close() {},
            writable: { getWriter: () => ({ async write() {}, releaseLock() {} }) },
            readable: { async pipeTo(sink) { await sink.getWriter().write(new Uint8Array([42])); } },
        };
    };
    context.remote = { value: null };
    context.socket = { readyState: 1, send(value) { sent.push(value); }, close() { this.readyState = 3; } };
    context.pips = pips;
    await vm.runInContext('handleTCPOutBound(remote, "www.cloudflare.com", 443, new Uint8Array([1]), socket, new Uint8Array([0,0]), {pips})', context);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(dialed.length, pips.length + 2, `NAT64 attempted after ${pips.length} relay(s)`);
    assert.match(dialed.at(-1), /^\[(2a02:898:146:64|2602:fc59:b0:64|2602:fc59:11:64)::6810:7c60\]$/);
    assert.equal(sent.length, 1, 'response returned through NAT64');
}
context.fetch = async () => ({ json: async () => ({ Answer: [{ type: 1, data: '10.0.0.1' }] }) });
await assert.rejects(vm.runInContext('nat64Address("internal.example.com", "2a02:898:146:64::")', context), /no public IPv4/);
console.log('Worker NAT64: used without a relay and after a failing relay; private answers refused.');

// Two of three NAT64 gateways dead (one refuses, one never opens): the third still carries the site.
for (let run = 0; run < 12; run++) {
    const dialed = [];
    const sent = [];
    context.setTimeout = (fn) => setImmediate(fn); // the connect timeout fires on the next turn
    context.fetch = async () => ({ json: async () => ({ Answer: [{ type: 1, data: '104.16.124.96' }] }) });
    context.connect = ({ hostname }) => {
        dialed.push(hostname);
        if (!hostname.startsWith('[2')) throw new Error('blocked');
        if (hostname.startsWith('[2a02:898:146:64')) throw new Error('gateway down');
        const hangs = hostname.startsWith('[2602:fc59:11:64');
        return {
            opened: hangs ? new Promise(() => {}) : Promise.resolve(),
            closed: new Promise(() => {}),
            close() {},
            writable: { getWriter: () => ({ async write() {}, releaseLock() {} }) },
            readable: { async pipeTo(sink) { await sink.getWriter().write(new Uint8Array([42])); } },
        };
    };
    context.remote = { value: null };
    context.socket = { readyState: 1, send(value) { sent.push(value); }, close() { this.readyState = 3; } };
    await vm.runInContext('handleTCPOutBound(remote, "www.cloudflare.com", 443, new Uint8Array([1]), socket, new Uint8Array([0,0]), {pips: []})', context);
    for (let i = 0; i < 50 && !sent.length; i++) await new Promise(resolve => setImmediate(resolve));
    assert.equal(sent.length, 1, `run ${run}: response returned through the working gateway (dialed ${dialed.join(' ')})`);
    assert.match(dialed.at(-1), /^\[2602:fc59:b0:64::6810:7c60\]$/);
}
console.log('Worker NAT64: every gateway is tried in turn; dead or silent gateways do not fail the site.');
