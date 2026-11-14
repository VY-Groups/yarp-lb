import {test, expect} from '@playwright/test';

// Real Chromium against the real, separate GatewayCore Kestrel process.
// No HTML mocks, no page.route(), no mocked /admin/api responses.
test('browser: bootstrap, navigation, onboarding, websites, route edit, users and reset', async ({page}) => {
  const pageErrors=[];
  page.on('pageerror',error=>pageErrors.push(String(error)));

  await page.goto('/dashboard', {waitUntil:'domcontentloaded'});
  await expect(page.locator('#auth-screen')).toBeVisible();
  await expect(page.locator('#auth-title')).toContainText('Create initial administrator');
  await page.locator('#auth-username').fill('browseradmin');
  await page.locator('#auth-email').fill('browseradmin@example.invalid');
  await page.locator('#auth-password').fill('Browser-secret-long-4096!');
  await page.locator('#auth-submit').click();
  await expect(page.locator('#app-shell')).toBeVisible();
  await expect(page.locator('#user-badge')).toContainText('browseradmin');

  await test.step('Setup Center page shows live setup state',async()=>{
    await page.locator('button.nav[data-view="setup"]').click();
    await expect(page.locator('#content')).toContainText('FIRST-RUN BOOTSTRAP');
    await expect(page.locator('#content')).toContainText('Set up your YARP gateway');
  });

  await test.step('Architecture has working back and hosting choices',async()=>{
    await page.locator('button.nav[data-view="onboarding"]').click();
    await expect(page.locator('#content')).toContainText('Gateway onboarding');
    await expect(page.locator('[data-action="setup-prev"]')).toContainText('Exit to Setup Center');
    await page.locator('[data-action="setup-step"][data-id="2"]').click();
    await expect(page.locator('#content')).toContainText('Hosting engine');
    await expect(page.locator('#content')).toContainText('Microsoft IIS');
    await expect(page.locator('#content')).toContainText('Apache httpd');
    await expect(page.locator('#content')).toContainText('Nginx');
    await page.locator('#page-back').click();
    await expect(page.locator('#page-title')).toContainText('Setup Center');
  });

  // Seed ONLY the architecture metadata through the real authenticated API
  // so this UI test can exercise the independent websites/forms. The separate
  // HTTP E2E test already checks revision conflicts and RBAC for this endpoint.
  await page.evaluate(async () => {
    const session=await (await fetch('/admin/api/session')).json();
    const current=await (await fetch('/admin/api/onboarding')).json();
    const plan={
      mode:'standalone',controlPlane:'local',dataStore:'local-file',
      accessPattern:'segmented',
      gateways:[{id:'browser-gateway',hostname:'127.0.0.1',agentUrl:''}],
      workloads:[{id:'browser-origin',application:'browser-site',
        url:'http://127.0.0.1/',zone:'public',hostingEngine:'iis'}]
    };
    const r=await fetch('/admin/api/onboarding',{
      method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},
      body:JSON.stringify({plan,expectedRevision:current.revision,confirmDesign:true})
    });
    if(!r.ok)throw Error('Real API topology confirmation failed: '+r.status+': '+await r.text());
  });
  await page.reload({waitUntil:'domcontentloaded'});
  await expect(page.locator('#app-shell')).toBeVisible();
  await page.locator('button.nav[data-view="setup"]').click();

  await test.step('Add Website supports Apache/Nginx/IIS and exits cleanly',async()=>{
    await page.locator('[data-action="setup-local-web"]').click();
    await expect(page.locator('#modal')).toBeVisible();
    await expect(page.locator('#modal-title')).toContainText('IIS, Apache, Nginx');
    await expect(page.locator('#f-hosting')).toContainText('Apache httpd');
    await page.locator('#f-hosting').selectOption('Apache httpd');
    await page.locator('#f-id').fill('browser-local');
    await page.locator('#f-origin').fill('http://127.0.0.1/');
    await page.locator('#confirm').click();
    await expect(page.locator('#modal')).toBeHidden();
    await expect(page.locator('#page-subtitle')).toContainText('Unsaved');

    await page.locator('[data-action="setup-add-application"]').click();
    await expect(page.locator('#modal-title')).toContainText('Advanced public HTTPS application');
    await expect(page.locator('#f-hosting')).toContainText('Kubernetes Ingress (external)');
    await page.locator('#modal-close').click();
    await expect(page.locator('#modal')).toBeHidden();
  });

  await test.step('Edit Route allows optional hostname and a visible Cancel',async()=>{
    await page.locator('button.nav[data-view="routes"]').click();
    await expect(page.locator('#content')).toContainText('Routes');
    await page.locator('[data-action="route-edit"]').first().click();
    await expect(page.locator('#modal-title')).toContainText('Edit route');
    await expect(page.locator('#f-hosts')).not.toHaveAttribute('required');
    await page.locator('#f-hosts').fill('');
    await page.locator('#editor button[value="cancel"]').click();
    await expect(page.locator('#modal')).toBeHidden();
    await page.locator('#page-back').click();
    await expect(page.locator('#page-title')).toContainText('Setup Center');
  });

  await test.step('Create account and Reset Password submit real API requests',async()=>{
    await page.locator('button.nav[data-view="users"]').click();
    await expect(page.locator('#content')).toContainText('Administrator accounts');
    await page.locator('[data-action="user-add"]').click();
    await expect(page.locator('#modal-title')).toContainText('Create management user');
    await page.locator('#f-username').fill('browser_viewer');
    await page.locator('#f-role').selectOption('Viewer');
    await page.locator('#f-email').fill('browser_viewer@example.invalid');
    await page.locator('#f-password').fill('Browser-viewer-long-pass!');
    await page.locator('#confirm').click();
    await expect(page.locator('#modal')).toBeHidden();
    await expect(page.locator('#content')).toContainText('browser_viewer');
    await page.locator('[data-action="password-reset"][data-id="browser_viewer"]').click();
    await expect(page.locator('#modal-title')).toContainText('Reset browser_viewer password');
    await expect(page.locator('#confirm')).toHaveText('Reset password');
    await expect(page.locator('#f-password')).toHaveAttribute('minlength','16');
    await page.locator('#f-password').fill('Changed-browser-viewer-pass!');
    await page.locator('#confirm').click();
    await expect(page.locator('#modal')).toBeHidden();
    await expect(page.locator('#content')).toContainText('browser_viewer');
  });

  await test.step('All major management screens render without JS exceptions',async()=>{
    for(const view of ['overview','clusters','backends','health','metrics',
      'inventory','approvals','backups','mail','directory','fleet','capabilities','featurematrix']){
      const nav=page.locator('button.nav[data-view="'+view+'"]');
      await nav.click();
      await expect(page.locator('#page-title')).not.toBeEmpty();
      await expect(page.locator('#content')).not.toBeEmpty();
    }
    await expect(page.locator('#app-shell')).toBeVisible();
  });

  expect(pageErrors,'Unhandled JavaScript exceptions in real Chromium').toEqual([]);
});
