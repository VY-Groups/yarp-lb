// Disposable real Chromium acceptance, invoked only by the live-Raft fixture.
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted')
    throw new Error('Disposable hosted CI only');
const chunks=[];
for await (const chunk of process.stdin) chunks.push(chunk);
const fixture=JSON.parse(Buffer.concat(chunks).toString('utf8'));
if (!/^https:\/\/127\.0\.0\.1:[0-9]+$/.test(fixture.origin))
    throw new Error('Disposable loopback origin required');
const browser=await chromium.launch({headless:true});
try {
    // Fixture-only server trust exception. Python separately validates the
    // generated CA and hostname; server-side client mTLS remains mandatory.
    const context=await browser.newContext({
        ignoreHTTPSErrors:true,acceptDownloads:true,
        clientCertificates:[{origin:fixture.origin,certPath:fixture.certificate,keyPath:fixture.key}]
    });
    try {
        const page=await context.newPage();
        page.setDefaultTimeout(20000);
        const errors=[];
        page.on('pageerror',()=>errors.push('browser execution error'));
        let downloads=0;
        page.on('download',()=>downloads++);
        const document=await page.goto(fixture.origin+'/dashboard',{waitUntil:'domcontentloaded'});
        assert.equal(document?.status(),200,'real browser dashboard document status');
        assert.equal(new URL(page.url()).pathname,'/dashboard','unexpected dashboard redirect');
        assert.equal(await page.evaluate(()=>isSecureContext && !!globalThis.crypto?.subtle),true,
            'browser management context must support SHA-256');
        await page.locator('#auth-username').waitFor({state:'visible'});
        await page.locator('#auth-username').fill('vip-policy-admin');
        await page.locator('#auth-password').fill(fixture.password);
        await page.locator('#auth-submit').click();
        await page.locator('#app-shell:visible, #privacy-screen:visible').first().waitFor();
        if(await page.locator('#privacy-screen').isVisible())
            await page.locator('#privacy-accept').click();
        await page.locator('#app-shell').waitFor({state:'visible'});
        // The shell becomes visible before asynchronous session initialization
        // finishes. Wait for the initial configuration render before navigation.
        await page.locator('#notice').filter({hasText:'Latest configuration loaded'}).waitFor({state:'visible'});
        assert.match(await page.locator('#user-badge').innerText(),/Administrator/);
        const nav=page.locator('button.nav[data-view="inventory"]');
        const parent=nav.locator('xpath=ancestor::details');
        if(await parent.count() && await parent.getAttribute('open')===null)
            await parent.locator('summary').click();
        await nav.waitFor({state:'visible'});
        const [inventoryResponse]=await Promise.all([
            page.waitForResponse(r=>r.url()===fixture.origin+'/admin/api/network/interfaces'&&r.request().method()==='GET'),
            nav.click()
        ]);
        assert.equal(inventoryResponse.status(),200,'real authenticated browser inventory');
        const inventory=await inventoryResponse.json();
        assert.ok(inventory.virtualAddresses.some(item=>item.haPolicyScope===fixture.policy.scope),
            'browser inventory must contain the exact journal-bound scope');
        assert.equal(await nav.getAttribute('aria-current'),'page','inventory navigation must remain selected');
        await page.getByRole('heading',{name:'Independent HA policy',exact:true}).waitFor({state:'visible'});
        const recovery=page.locator('#ha-recovery-panel');
        await recovery.getByRole('heading',{name:'Independent HA recovery handoff'}).waitFor({state:'visible'});
        assert.match(await recovery.innerText(),/Independent controller — not verified here/);
        assert.match(await recovery.innerText(),/Never reset the journal/);
        assert.ok(inventory.virtualAddresses.some(item=>item.haPolicyScope===fixture.policy.scope &&
            item.recoveryAuthority==='independent-controller' && item.recoveryVerified===false));
        const policy=fixture.policy;
        await page.locator('#ha-scope').selectOption(policy.scope);
        await page.locator('#ha-preferred').fill(policy.preferredPin);
        await page.locator('#ha-other').fill(policy.otherPin);
        await page.locator('#ha-failback').setChecked(policy.failbackEnabled);
        await page.locator('#ha-rearm').setChecked(policy.rearmEnabled);
        for(const [id,key] of [['poll','pollSeconds'],['samples','failureSamples'],
            ['failure','failureSeconds'],['eligible','failbackEligibleSeconds'],['owner','minimumOwnerSeconds']])
            await page.locator('#ha-'+id).fill(String(policy[key]));
        const button=page.locator('[data-action="ha-policy-export"]');
        const response=()=>page.waitForResponse(r=>r.url()===fixture.origin+'/admin/api/network/virtual-services/ha-policy'&&r.request().method()==='POST');
        await page.locator('#ha-poll').fill('1');
        const [denied]=await Promise.all([response(),button.click()]);
        assert.equal(denied.status(),400,'unsafe timing must be denied by actual server');
        // The actual UI error must be displayed; never allow download on denial.
        await page.locator('#notice').filter({hasText:/Invalid HA policy/i}).waitFor({state:'visible'});
        assert.equal(downloads,0);
        await page.locator('#ha-poll').fill(String(policy.pollSeconds));
        const [accepted,download]=await Promise.all([response(),page.waitForEvent('download'),button.click()]);
        assert.equal(accepted.status(),200);
        assert.equal(download.suggestedFilename(),'gatewaycore-ha-policy.json');
        assert.equal(await download.failure(),null);
        const bytes=await fs.readFile(await download.path());
        assert.equal(bytes.toString('utf8'),fixture.expectedJson);
        assert.equal(createHash('sha256').update(bytes).digest('hex').toUpperCase(),fixture.expectedSha256);
        assert.deepEqual(JSON.parse(bytes.toString('utf8')),policy);
        assert.equal(downloads,1);
        assert.equal(errors.length,0);
        console.log('PASS: real Chromium authenticated HA policy form, unsafe timing denial, exact downloaded bytes and audited digest');
    } finally { await context.close(); }
} finally { await browser.close(); }
