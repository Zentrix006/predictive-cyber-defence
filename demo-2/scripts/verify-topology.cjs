// Run against the Docker frontend. PLAYWRIGHT_MODULE may point to a local install.
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const base = process.env.TOPOLOGY_TEST_URL || 'http://localhost:3000';

function capture() {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4); header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16); header.writeUInt32LE(1, 20);
  const parts = [header];
  for (let i = 0; i < 3; i++) {
    const packet = Buffer.alloc(42);
    packet.writeUInt16BE(0x0800, 12); packet[14] = 0x45; packet.writeUInt16BE(28, 16);
    packet[22] = 64; packet[23] = 17;
    Buffer.from([10, 0, 0, 1]).copy(packet, 26);
    Buffer.from([10, 0, 0, i === 2 ? 3 : 2]).copy(packet, 30);
    packet.writeUInt16BE(40000, 34); packet.writeUInt16BE(53, 36); packet.writeUInt16BE(8, 38);
    const record = Buffer.alloc(16); record.writeUInt32LE(1700000000 + i, 0);
    record.writeUInt32LE(packet.length, 8); record.writeUInt32LE(packet.length, 12);
    parts.push(record, packet);
  }
  return Buffer.concat(parts);
}

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    const api = page.request;
    const login = await api.post(`${base}/api/v1/auth/login`, { data: { username: process.env.TEST_ADMIN_USER || 'dev', password: process.env.TEST_ADMIN_PASSWORD || '197' } });
    assert.equal(login.status(), 200);
    const session = await login.json();
    const elevated = await api.post(`${base}/api/v1/auth/elevate`, { headers: { Authorization: `Bearer ${session.access_token}` }, data: { password: process.env.TEST_ADMIN_PASSWORD || '197' } });
    assert.equal(elevated.status(), 200); const admin = await elevated.json();
    await page.addInitScript(s => { sessionStorage.setItem('pcd.access_token', s.access_token); sessionStorage.setItem('pcd.session', JSON.stringify(s)); }, admin);
    const fixtureNodes = ['10.1.0.1', '10.1.0.2'].map(id => ({ id, asset_id: id, label: id, asset_type: 'server', zone: 'server_zone', status: 'normal', criticality: 'low', threat_score: 0, metadata: {ip: id} }));
    // Controlled live response lets the poll/position regression be reproduced.
    await page.route('**/api/v1/topology', route => route.fulfill({ json: { nodes: fixtureNodes, edges: [{id: 'live-edge', source: fixtureNodes[0].id, target: fixtureNodes[1].id, protocol: 'TCP', packet_count: 2, bytes_transferred: 100}], prediction_edges: [] } }));
    await page.goto(base);
    await page.waitForFunction(() => document.querySelector('[data-testid="topology-canvas"]')?._cyreg?.cy?.nodes().length === 2);
    const graph = fn => page.evaluate(fn);
    const zoom = () => graph(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.zoom());
    const workspace = page.getByRole('region', {name:'Network topology workspace'});
    await page.getByRole('button', { name: 'Fit topology to screen', exact: true }).click();
    const before = await zoom();
    await page.getByRole('button', { name: 'Zoom out topology', exact: true }).click(); assert.ok(await zoom() < before);
    await page.getByRole('button', { name: 'Zoom in topology', exact: true }).click(); assert.ok(Math.abs(await zoom() - before) < 0.001);
    for (const layout of ['grid', 'circle', 'dagre', 'criticality', 'cose-bilkent']) {
      await page.getByLabel('Topology layout', {exact:true}).selectOption(layout);
      await page.waitForFunction(l => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy._prevLayout === l, layout);
    }
    const positions = await graph(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.nodes().map(n => n.position()));
    await page.waitForTimeout(4500);
    assert.deepEqual(await graph(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.nodes().map(n => n.position())), positions);
    await page.getByRole('button', {name:'Maximize topology', exact:true}).click();
    assert.deepEqual(await workspace.boundingBox(), {x:0, y:0, width:1440, height:1000});
    await page.getByRole('button', {name:'Minimize topology', exact:true}).click(); assert.ok((await workspace.boundingBox()).width < 1440);
    await page.getByRole('button', {name:'Maximize topology', exact:true}).click();
    await page.keyboard.press('Escape'); assert.ok((await workspace.boundingBox()).width < 1440);
    await page.getByRole('button', {name:'Enter fullscreen', exact:true}).click();
    await page.waitForFunction(() => !!document.fullscreenElement);
    await page.getByRole('button', {name:'Exit fullscreen', exact:true}).click(); await page.waitForFunction(() => !document.fullscreenElement);
    await page.evaluate(() => { Element.prototype.requestFullscreen = () => Promise.reject(new Error('test denied')); });
    await page.getByRole('button', {name:'Enter fullscreen', exact:true}).click();
    await page.getByRole('button', {name:'Minimize topology', exact:true}).waitFor();
    await page.keyboard.press('Escape'); assert.ok((await workspace.boundingBox()).width < 1440);
    console.log('PASS graph initialization, poll stability, layouts, zoom/fit, maximize/minimize, Escape, native fullscreen and fallback');

    const upload = { name: 'topology-test.pcap', mimeType: 'application/octet-stream', buffer: capture() };
    await page.getByLabel('Upload topology capture', {exact:true}).setInputFiles(upload);
    await page.getByRole('button', {name:'Return to live', exact:true}).waitFor();
    await page.waitForFunction(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.nodes().length === 3);
    await page.getByRole('button', {name:'Maximize topology', exact:true}).click();
    await page.getByRole('button', {name:'Play replay', exact:true}).click();
    await page.waitForTimeout(250); await page.getByRole('button', {name:'Pause replay', exact:true}).click();
    await page.getByLabel('Replay position', {exact:true}).fill('2');
    await page.waitForFunction(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.edges().reduce((n,e) => n + e.data('packets'), 0) === 3);
    await page.getByRole('button', {name:'Reset replay', exact:true}).click(); assert.equal(await page.getByLabel('Replay position', {exact:true}).inputValue(), '0');
    await page.getByLabel('Replay speed', {exact:true}).selectOption('100');
    await page.getByRole('button', {name:'Play replay', exact:true}).click();
    await page.waitForFunction(() => document.querySelector('input[aria-label="Replay position"]').value === '2');
    const point = await graph(() => {const el = document.querySelector('[data-testid="topology-canvas"]'); const p = el._cyreg.cy.nodes()[0].renderedPosition(); const r = el.getBoundingClientRect(); return {x:r.x+p.x, y:r.y+p.y};});
    await page.mouse.click(point.x, point.y);
    await page.getByLabel('Node details', {exact:true}).waitFor(); assert.equal(await page.getByRole('button', {name:'Isolate Asset', exact:true}).isDisabled(), true);
    await page.getByRole('button', {name:'Close node details', exact:true}).click();
    await page.getByRole('button', {name:'Open minimap', exact:true}).click();
    await page.getByRole('button', {name:'Close minimap', exact:true}).click();
    await page.getByRole('button', {name:'Minimize topology', exact:true}).click();
    await page.getByRole('button', {name:'Switch to light mode', exact:true}).click();
    await page.getByRole('button', {name:'Maximize topology', exact:true}).click();
    assert.equal(await graph(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.nodes()[0].style('color')), 'rgb(15,23,42)');
    await page.screenshot({path:'/tmp/topology-light-replay.png'});
    await page.setViewportSize({width:390,height:844});
    await page.waitForFunction(() => {
      const cy = document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy;
      return cy.nodes().every(n => { const p = n.renderedPosition(); return p.x > 0 && p.x < cy.width() && p.y > 0 && p.y < cy.height(); });
    });
    assert.equal((await workspace.boundingBox()).width, 390);
    for (const name of ['Minimize topology','Enter fullscreen']) { const box = await page.getByRole('button',{name,exact:true}).boundingBox(); assert.ok(box.x >= 0 && box.x + box.width <= 390); }
    await page.screenshot({path:'/tmp/topology-mobile-replay.png'});
    await page.getByRole('button',{name:'Return to live',exact:true}).click();
    await page.waitForFunction(() => document.querySelector('[data-testid="topology-canvas"]')._cyreg.cy.nodes().length === 2);
    assert.deepEqual(errors, []);
    console.log('PASS real PCAP upload, replay/play/pause/seek/reset/speed, node details, minimap, light theme, mobile controls, return to live; no browser exceptions');

    const guest = await (await api.post(`${base}/api/v1/auth/guest`)).json();
    const denied = await api.post(`${base}/api/v1/topology/pcap`, { headers: {Authorization:`Bearer ${guest.access_token}`}, multipart:{file: {name:'test.pcap',mimeType:'application/octet-stream',buffer:capture()}} });
    assert.equal(denied.status(),403);
    const bad = await api.post(`${base}/api/v1/topology/pcap`, { headers: {Authorization:`Bearer ${admin.access_token}`}, multipart:{file: {name:'bad.pcap',mimeType:'application/octet-stream',buffer:Buffer.from('invalid')}} });
    assert.equal(bad.status(),400);
    console.log('PASS guest upload denied and malformed capture rejected');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
