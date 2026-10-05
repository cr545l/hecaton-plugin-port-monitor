const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const dgram = require('node:dgram');
const { execFile } = require('node:child_process');
const source = fs.readFileSync(require('node:path').join(__dirname, '../main.js'), 'utf8')
  .replace(/^#!.*\n/, '').replace(/\nmain\(\);\s*$/, '');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const exec = ({ program, args, timeout_ms }) => new Promise(resolve => {
  execFile(program, args, { timeout: timeout_ms }, (error, stdout, stderr) => {
    resolve({ ok: !error, exit_code: error ? error.code : 0, stdout, stderr });
  });
});
async function load(platform = 'darwin', run = exec) {
  const noop = async () => ({});
  const hecaton = {
    env: { get: async () => ({ value: '' }) },
    process: { exec: run }, on() {},
    window: { set_title: noop, set_minimized_label: noop },
    dialog: { show: noop },
  };
  return new AsyncFunction('hecaton', 'process', source + `
    return { parseLsof, collectMacPorts, collectPortData, findPortOwners, getProcessSnapshot,
      taskkillTree, canKillPid, getEntries: () => portEntries, getError: () => collectionError };
  `)(hecaton, { platform, pid: process.pid, stdout: { write() {} } });
}

test('lsof parsing preserves names, IPv6, TCP state and UDP peers', async () => {
  const api = await load();
  const entries = api.parseLsof('p123\ncMy Process\nf8\nPTCP\nn[::1]:8080\nTST=LISTEN\nf9\nPTCP\nn127.0.0.1:8080->127.0.0.1:50001\nTST=ESTABLISHED\np456\ncUDP Server\nf3\nPUDP\nn*:5353\nf4\nPUDP\nn[::1]:6000->[::1]:7000\n');
  assert.equal(entries.length, 4);
  assert.deepEqual(entries[0], { proto: 'TCP', localIp: '[::1]', localPort: '8080', remoteIp: '*', remotePort: '*', state: 'LISTENING', pid: '123', processName: 'My Process' });
  assert.equal(entries[1].remotePort, '50001');
  assert.equal(entries[1].state, 'ESTABLISHED');
  assert.equal(entries[2].state, '');
  assert.equal(entries[3].remotePort, '7000');
});

test('Windows collection still parses netstat and tasklist', async () => {
  const api = await load('win32', async ({ program }) => ({ ok: true, stdout: program === 'tasklist'
    ? '"server.exe","123","Console","1","100 K"\n'
    : 'TCP 127.0.0.1:8080 0.0.0.0:0 LISTENING 123\nUDP [::]:5353 *:* 456\n' }));
  await api.collectPortData();
  assert.equal(api.getEntries().length, 2);
  assert.equal(api.getEntries()[0].processName, 'server.exe');
  assert.equal(api.getEntries()[1].pid, '456');
});

test('collection failure keeps previous data and surfaces an error', async () => {
  let fail = false;
  const api = await load('darwin', async () => fail ? { ok: false, stderr: 'denied' } : { ok: true, stdout: 'p123\ncServer\nf3\nPTCP\nn*:8080\nTST=LISTEN\n' });
  await api.collectPortData();
  fail = true;
  await api.collectPortData();
  assert.equal(api.getEntries().length, 1);
  assert.match(api.getError(), /lsof failed/);
  await assert.rejects(api.findPortOwners('TCP', '8080'), /lsof failed/);
  fail = false;
  await api.collectPortData();
  assert.equal(api.getError(), '');
});

test('macOS process termination targets descendants first and protects system PIDs', async () => {
  const calls = [];
  const api = await load('darwin', async (request) => {
    calls.push(request);
    return { ok: true, stdout: request.program === '/bin/ps' ? '100 1 /app/Server Name\n101 100 /app/Worker\n102 101 /app/Child\n' : '' };
  });
  assert.equal(api.canKillPid('1'), false);
  assert.equal(api.canKillPid('0'), false);
  assert.equal(api.canKillPid(String(process.pid)), false);
  assert.equal(api.canKillPid('-1'), false);
  assert.equal(await api.taskkillTree('1'), false);
  await api.taskkillTree('100');
  assert.deepEqual(calls.filter(c => c.program === '/bin/kill').map(c => c.args), [['-TERM', '102'], ['-TERM', '101'], ['-TERM', '100']]);
  calls.length = 0;
  await api.taskkillTree('100', true);
  assert.ok(calls.filter(c => c.program === '/bin/kill').every(c => c.args[0] === '-KILL'));
});

test('macOS live collection finds local TCP and UDP sockets with owning PID', { skip: process.platform !== 'darwin' }, async () => {
  const server = net.createServer();
  const udp = dgram.createSocket('udp4');
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    await new Promise(resolve => udp.bind(0, '127.0.0.1', resolve));
    const api = await load();
    const entries = await api.collectMacPorts();
    for (const [proto, port] of [['TCP', server.address().port], ['UDP', udp.address().port]]) {
      const entry = entries.find(e => e.proto === proto && e.localPort === String(port) && e.pid === String(process.pid));
      assert.ok(entry, `Missing ${proto} socket`);
      assert.ok(entry.processName);
      if (proto === 'TCP') assert.equal(entry.state, 'LISTENING');
    }
    assert.ok((await api.getProcessSnapshot()).some(p => p.pid === String(process.pid)));
  } finally {
    await new Promise(resolve => server.close(resolve));
    udp.close();
  }
});
