// SPDX-License-Identifier: GPL-3.0-only
// Adapted from bia-pain-bache/BPB-VPN worker/worker.js, commit 381df1270e3b81feaa7a878603ae049cf79a560f.
// Changes: destination validation, bounded header buffering, awaited TCP setup, user relay first, then public NAT64 fallback
// across every gateway in turn, with a connect timeout.
import { connect } from 'cloudflare:sockets';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

export default {
    async fetch(request, env, ctx) {
        try {
            const settings = readSettings(env);
            if (!settings) return new Response('Not found', { status: 404 });

            const upgrade = request.headers.get('Upgrade');
            if (upgrade && upgrade.toLowerCase() === 'websocket') {
                return vOverWS(request, settings);
            }
            return fallback(request, settings);
        } catch {
            return new Response('Internal error', { status: 500 });
        }
    },
};

function readSettings(env) {
    try {
        const data = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(env.ENV), (c) => c.charCodeAt(0))));
        if (!data || data.v !== 1 || typeof data.id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(data.id)) return null;
        const pips = (Array.isArray(data.pips) ? data.pips : [])
            .map((s) => String(s).trim())
            .filter(Boolean);

        return {
            id: data.id.toLowerCase(),
            pips,
            fb: String(data.fb || '').trim(),
        };
    } catch {
        return null;
    }
}

async function fallback(request, settings) {
    if (settings.fb) {
        try {
            const target = new URL(settings.fb);
            const url = new URL(request.url);
            url.protocol = target.protocol;
            url.hostname = target.hostname;
            url.port = target.port;
            return fetch(new Request(url, request));
        } catch {
            // Fall through to the default page.
        }
    }
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
}

async function vOverWS(request, settings) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    webSocket.binaryType = 'arraybuffer';

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

    const remoteSocket = { value: null };
    let pending = new Uint8Array(0);

    readableWebSocketStream
        .pipeTo(new WritableStream({
            async write(chunk) {
                if (remoteSocket.value) {
                    const writer = remoteSocket.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }

                const incoming = new Uint8Array(chunk);
                if (pending.byteLength + incoming.byteLength > 1048576) throw new Error('initial data too large');
                const combined = new Uint8Array(pending.byteLength + incoming.byteLength);
                combined.set(pending);
                combined.set(incoming, pending.byteLength);
                pending = combined;
                const header = parseVHeader(pending.buffer, settings.id);
                if (header.incomplete) return;
                if (header.hasError) throw new Error(header.message);

                const responseHeader = new Uint8Array([header.version[0], 0]);
                const rawClientData = pending.buffer.slice(header.rawDataIndex);
                pending = new Uint8Array(0);

                await handleTCPOutBound(remoteSocket, header.addressRemote, header.portRemote, rawClientData, webSocket, responseHeader, settings);
            },
            close() {
                safeCloseTcpSocket(remoteSocket.value);
            },
        }))
        .catch(() => {
            safeCloseTcpSocket(remoteSocket.value);
            safeCloseWebSocket(webSocket);
        });

    // Browsers drop a WebSocket whose subprotocol (Xray's early data) isn't echoed back.
    const headers = earlyDataHeader ? { 'Sec-WebSocket-Protocol': earlyDataHeader } : undefined;
    return new Response(null, { status: 101, webSocket: client, headers });
}

function parseVHeader(buffer, userId) {
    if (buffer.byteLength < 19) return { incomplete: true };

    const bytes = new Uint8Array(buffer);
    const version = bytes.slice(0, 1);
    if (uuidFromBytes(bytes, 1) !== userId) return { hasError: true, message: 'invalid user' };

    const optLength = bytes[17];
    if (buffer.byteLength < 22 + optLength) return { incomplete: true };
    const command = bytes[18 + optLength];
    // TCP only: the client blocks UDP and resolves DNS over DoH through TCP.
    if (command !== 1) {
        return { hasError: true, message: `command ${command} is not supported` };
    }

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);

    if (!portRemote) return { hasError: true, message: 'invalid port' };
    const addressType = bytes[portIndex + 2];
    let addressValueIndex = portIndex + 3;
    let addressLength = 0;
    let addressRemote = '';

    switch (addressType) {
        case 1:
            addressLength = 4;
            if (buffer.byteLength < addressValueIndex + addressLength) return { incomplete: true };
            addressRemote = bytes.slice(addressValueIndex, addressValueIndex + 4).join('.');
            break;
        case 2:
            if (buffer.byteLength < addressValueIndex + 1) return { incomplete: true };
            addressLength = bytes[addressValueIndex];
            if (!addressLength) return { hasError: true, message: 'empty address' };
            addressValueIndex += 1;
            if (buffer.byteLength < addressValueIndex + addressLength) return { incomplete: true };
            addressRemote = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: {
            addressLength = 16;
            if (buffer.byteLength < addressValueIndex + addressLength) return { incomplete: true };
            const view = new DataView(buffer.slice(addressValueIndex, addressValueIndex + 16));
            const parts = [];
            for (let i = 0; i < 8; i++) parts.push(view.getUint16(i * 2).toString(16));
            addressRemote = parts.join(':');
            break;
        }
        default:
            return { hasError: true, message: `invalid address type ${addressType}` };
    }

    if (!publicDestination(addressRemote)) return { hasError: true, message: 'destination is not public' };

    return {
        hasError: false,
        addressRemote,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        version,
    };
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));

function uuidFromBytes(arr, offset) {
    const h = (i) => byteToHex[arr[offset + i]];
    return (
        h(0) + h(1) + h(2) + h(3) + '-' + h(4) + h(5) + '-' + h(6) + h(7) + '-' +
        h(8) + h(9) + '-' + h(10) + h(11) + h(12) + h(13) + h(14) + h(15)
    );
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, settings) {
    async function connectAndWrite(address, port) {
        if (address.includes(':') && !address.startsWith('[')) address = `[${address}]`;
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        tcpSocket.closed.catch(() => { });
        // A dead gateway never opens; give up so the next fallback gets its turn.
        if (tcpSocket.opened) {
            await Promise.race([tcpSocket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error('connect timed out')), CONNECT_TIMEOUT_MS))]);
        }
        const writer = tcpSocket.writable.getWriter();
        try { await writer.write(rawClientData); }
        finally { writer.releaseLock(); }
        return tcpSocket;
    }

    // Cloudflare-hosted targets refuse direct connections from Workers. Retry through
    // the user's proxy IP when one is set, then through a public NAT64 gateway.
    async function viaProxyIp() {
        const { host, port } = parseHostPort(randomItem(settings.pips));
        if (!publicDestination(host)) throw new Error('relay is not public');
        return connectAndWrite(host, port);
    }

    // Every gateway, in random order: public NAT64 gateways go down, and one dead one must not fail the site.
    const viaNat64 = shuffled(NAT64_PREFIXES).map((prefix) =>
        async () => connectAndWrite(await nat64Address(addressRemote, prefix), portRemote));

    const fallbacks = (settings.pips.length ? [viaProxyIp] : []).concat(viaNat64);

    async function retry(index = 0) {
        safeCloseTcpSocket(remoteSocket.value);
        if (index >= fallbacks.length) return safeCloseWebSocket(webSocket);
        const next = index + 1 < fallbacks.length ? () => retry(index + 1) : null;
        try {
            remoteSocketToWS(await fallbacks[index](), webSocket, responseHeader, next);
        } catch (error) {
            if (next) await next();
            else webSocket.close(1011, `Retry failed: ${error && error.message || error}`);
        }
    }

    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry);
    } catch (error) {
        await retry();
    }
}

const randomItem = (arr) => arr[Math.floor(Math.random() * arr.length)];
const shuffled = (arr) => arr.map((item) => [Math.random(), item]).sort((a, b) => a[0] - b[0]).map(([, item]) => item);
const CONNECT_TIMEOUT_MS = 5000;

// Public NAT64 gateways (the same defaults BPB ships). They see the destination, never the TLS content.
const NAT64_PREFIXES = ['2a02:898:146:64::', '2602:fc59:b0:64::', '2602:fc59:11:64::'];

async function nat64Address(address, prefix) {
    let ipv4 = /^[0-9.]+$/.test(address) ? address : '';
    if (!ipv4 && !address.includes(':')) {
        // fetch(), unlike connect(), may reach Cloudflare-hosted resolvers.
        const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(address)}&type=A`,
            { headers: { accept: 'application/dns-json' } });
        const answer = ((await response.json()).Answer || []).find((record) => record.type === 1);
        ipv4 = answer ? String(answer.data) : '';
    }
    if (!ipv4 || !publicDestination(ipv4)) throw new Error('no public IPv4 for NAT64');
    const hex = ipv4.split('.').map((part) => Number(part).toString(16).padStart(2, '0'));
    return `[${prefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry) {
    let header = responseHeader;
    let hasIncomingData = false;

    try {
        await remoteSocket.readable.pipeTo(new WritableStream({
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error('WebSocket is not open');
                }
                if (header) {
                    webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() {
                safeCloseTcpSocket(remoteSocket);
            },
        }));
    } catch {
        safeCloseTcpSocket(remoteSocket);
        if (hasIncomingData || !retry) safeCloseWebSocket(webSocket);
    }

    if (!hasIncomingData && retry) await retry();
    else safeCloseWebSocket(webSocket);
}

function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            webSocket.addEventListener('close', () => {
                safeCloseWebSocket(webSocket);
                if (!cancelled) controller.close();
            });
            webSocket.addEventListener('error', (err) => controller.error(err));

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            if (cancelled) return;
            cancelled = true;
            safeCloseWebSocket(webSocket);
        },
    });
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        const decoded = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
        return { earlyData: Uint8Array.from(decoded, (c) => c.charCodeAt(0)).buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

function safeCloseTcpSocket(socket) {
    try {
        if (socket) socket.close();
    } catch { }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close();
    } catch { }
}

function publicDestination(input) {
    const host = String(input).toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!host || host.includes('%') || host.includes('\\') || /[\x00-\x20\x7f]/.test(host)) return false;
    if (host.includes(':')) {
        // Public IPv6 global unicast only; mapped IPv4, local and metadata ranges are excluded.
        return /^[23][0-9a-f]{0,3}:[0-9a-f:]+$/.test(host) &&
            !host.startsWith('2001:db8:') && !host.startsWith('2002:');
    }
    if (/^[0-9.]+$/.test(host)) {
        const parts = host.split('.');
        if (parts.length !== 4 || parts.some(p => !/^(0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255)) return false;
        const [a, b] = parts.map(Number);
        return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && (b === 168 || b === 0)) || (a === 198 && (b === 18 || b === 19)));
    }
    return host.includes('.') && host.length <= 253 &&
        !/(^|\.)(localhost|local|internal|invalid|test)$/.test(host) &&
        host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function parseHostPort(input) {
    const match = String(input).trim().match(/^(?:\[(?<ipv6>.+?)\]|(?<host>[^:]+))(?::(?<port>\d+))?$/);
    if (!match) throw new Error(`Invalid host:port: ${input}`);
    const { ipv6, host, port } = match.groups;
    if (port && (Number(port) < 1 || Number(port) > 65535)) throw new Error('Invalid relay port');
    return {
        host: ipv6 ? `[${ipv6}]` : host,
        port: port ? Number(port) : 443
    };
}
