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

  await test.step('application builder creates separate pools and guards restricted services',async()=>{
    await page.locator('[data-action="setup-add-esign-pools"]').click();
    await expect(page.locator('#modal-title')).toContainText('Application public and private API pools');
    await expect(page.locator('#modal-help')).toContainText('Private host matching does not isolate network access');
    await page.locator('#f-id').fill('esign-browser');
    await page.locator('#f-mode').selectOption('primary-backup');
    await page.locator('#f-health').selectOption('passive-only');
    await page.locator('#confirm').click();
    await expect(page.locator('#modal')).toBeVisible();
    await expect(page.locator('#notice')).toContainText('Primary/DR standby requires active readiness checks');
    await page.locator('#f-health').selectOption('active');
    await page.locator('#f-publicHost').fill('esign.example.invalid');
    await page.locator('#f-privateHost').fill('esign.internal.example.invalid');
    await page.locator('#f-publicApp1').fill('https://esign-public-01.example.invalid/');
    await page.locator('#f-publicApp2').fill('https://esign-public-02.example.invalid/');
    await page.locator('#f-privateApp1').fill('https://esign-private-01.example.invalid/');
    await page.locator('#f-privateApp2').fill('https://esign-private-02.example.invalid/');
    await page.locator('#confirm').click();
    await expect(page.locator('#modal')).toBeHidden();
    await expect(page.locator('#notice')).toContainText('Added public and private eSign route and backend pool');
    await page.locator('button.nav[data-view="routes"]').click();
    await expect(page.locator('#content')).toContainText('esign-browser-public-route');
    await expect(page.locator('#content')).toContainText('esign-browser-private-route');
    await expect(page.locator('#content')).toContainText('esign-browser-public-pool');
    await expect(page.locator('#content')).toContainText('esign-browser-private-pool');
    await page.locator('button.nav[data-view="clusters"]').click();
    await expect(page.locator('#content')).toContainText('PrimaryBackup');
    await expect(page.locator('#content')).toContainText('Active');
    await page.locator('button.nav[data-view="backends"]').click();
    await expect(page.locator('#content')).toContainText('A host match separates routes');
    await expect(page.locator('#content')).toContainText('Inspect live health');
    await page.locator('[data-action="dest-drain"]').first().click();
    await expect(page.locator('#content')).toContainText('Draining');
    await expect(page.locator('#notice')).toContainText('unsaved draft');

    await page.locator('button.nav[data-view="setup"]').click();
    await page.locator('[data-action="setup-add-esign-pools"]').click();
    await page.locator('#f-id').fill('ra-browser');
    await page.locator('#f-service').selectOption('RA');
    await page.locator('#f-scope').selectOption('public-and-private');
    await page.locator('#confirm').click();
    await expect(page.locator('#modal')).toBeVisible();
    await expect(page.locator('#notice')).toContainText('RA must use the private-only pool scope');
    await page.locator('#f-scope').selectOption('private-only');
    await page.locator('#f-privateHost').fill('ra.internal.example.invalid');
    await page.locator('#f-privateApp1').fill('https://ra-01.example.invalid/');
    await page.locator('#f-privateApp2').fill('https://ra-02.example.invalid/');
    await page.locator('#confirm').click();
    await page.locator('button.nav[data-view="routes"]').click();
    await expect(page.locator('#content')).toContainText('ra-browser-private-route');
    await expect(page.locator('#content')).not.toContainText('ra-browser-public-route');

    await page.locator('button.nav[data-view="setup"]').click();
    await page.locator('[data-action="setup-add-esign-pools"]').click();
    await page.locator('#f-id').fill('ocsp-passive');
    await page.locator('#f-service').selectOption('OCSP');
    await page.locator('#f-scope').selectOption('public-only');
    await page.locator('#f-health').selectOption('passive-only');
    await page.locator('#f-publicHost').fill('ocsp.example.invalid');
    await page.locator('#f-publicApp1').fill('https://ocsp-01.example.invalid/');
    await page.locator('#f-publicApp2').fill('https://ocsp-02.example.invalid/');
    await expect(page.locator('#modal-help')).toContainText('bounded transport-failure ejection');
    await page.locator('#confirm').click();
    await expect(page.locator('#notice')).toContainText('two consecutive failures');
    await page.locator('button.nav[data-view="clusters"]').click();
    await expect(page.locator('#content')).toContainText('Passive only');
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
    await expect(page.locator('#page-title')).toContainText('Backend clusters');
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
      if(await nav.isHidden()){
        // A standalone topology intentionally hides Fleet; that is an access
        // guard, NOT missing or broken navigation.
        expect(view,'only standalone Fleet may be hidden').toBe('fleet');
        continue;
      }
      await nav.click();
      await expect(page.locator('#page-title')).not.toBeEmpty();
      await expect(page.locator('#content')).not.toBeEmpty();
    }
    await expect(page.locator('#app-shell')).toBeVisible();
  });

  await test.step('Short mobile viewport still reaches lower navigation entries',async()=>{
    await page.setViewportSize({width:390,height:667});
    await page.locator('button.nav[data-view="users"]').click();
    await expect(page.locator('#content')).toContainText('Administrator accounts');
    await page.locator('button.nav[data-view="mail"]').click();
    await expect(page.locator('#page-title')).toContainText('Mail & OTP');
  });

  await test.step('Zoho India SMTP profile uses SMTP host not webmail, with no credential autofill',async()=>{
    await page.locator('button.nav[data-view="mail"]').click();
    await expect(page.locator('#smtp-preset')).toBeVisible();
    await page.locator('#smtp-preset').selectOption('zoho-in-org');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtppro.zoho.in');
    // Re-clicking the already active page must not start a competing API
    // request that replaces a user's unsaved form edits.
    await page.locator('button.nav[data-view="mail"]').click();
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtppro.zoho.in');
    await expect(page.locator('#mail-config [name="port"]')).toHaveValue('587');
    await expect(page.locator('#mail-config [name="startTls"]')).toBeChecked();
    await expect(page.locator('#mail-config [name="password"]')).toHaveValue('');
    await expect(page.locator('#mail-config [name="enabled"]')).not.toBeChecked();
    await page.locator('#smtp-preset').selectOption('zoho-in-standard');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp.zoho.in');
  });

  await test.step('Gmail, Microsoft, Outlook and Exchange provider selection remains secure',async()=>{
    const preset=page.locator('#smtp-preset');
    await preset.selectOption('gmail');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp.gmail.com');
    await expect(page.locator('#mail-auth-mode')).toHaveValue('google-oauth');
    await expect(page.locator('#mail-config [name="oauthClientId"]')).toBeVisible();
    await expect(page.locator('#mail-config [name="password"]')).toHaveValue('');
    await expect(page.locator('#mail-config [name="enabled"]')).not.toBeChecked();
    await preset.selectOption('microsoft365');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp.office365.com');
    await expect(page.locator('#mail-auth-mode')).toHaveValue('microsoft-oauth');
    await preset.selectOption('outlook');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp-mail.outlook.com');
    await preset.selectOption('exchange');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('');
    await expect(page.locator('#mail-auth-mode')).toHaveValue('password');
    await expect(page.locator('#mail-config [name="oauthClientId"]')).toBeHidden();
    await preset.selectOption('yahoo');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp.mail.yahoo.com');
    await preset.selectOption('icloud');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp.mail.me.com');
    await preset.selectOption('fastmail');
    await expect(page.locator('#mail-config [name="host"]')).toHaveValue('smtp.fastmail.com');
    await expect(page.locator('#mail-config [name="enabled"]')).not.toBeChecked();
  });

  await test.step('Sign out, reject invalid password, and restore session',async()=>{
    let confirmedDiscard=false;
    page.once('dialog',async dialog=>{
      expect(dialog.message()).toContain('unsubmitted configuration draft');
      confirmedDiscard=true;
      await dialog.accept();
    });
    await page.locator('#logout').click();
    expect(confirmedDiscard,'Unsaved drafts require explicit confirmation').toBe(true);
    await expect(page.locator('#auth-screen')).toBeVisible();
    await expect(page.locator('#auth-username')).toHaveValue('');
    await expect(page.locator('#auth-password')).toHaveValue('');
    await expect(page.locator('#app-shell')).toBeHidden();
    await page.locator('#auth-username').fill('browseradmin');
    await page.locator('#auth-password').fill('Not-the-right-password-123!');
    await page.locator('#auth-submit').click();
    await expect(page.locator('#auth-message')).toContainText('Authentication failed');
    await expect(page.locator('#app-shell')).toBeHidden();
    await page.locator('#auth-password').fill('Browser-secret-long-4096!');
    await page.locator('#auth-submit').click();
    await expect(page.locator('#app-shell')).toBeVisible();
  });

  expect(pageErrors,'Unhandled JavaScript exceptions in real Chromium').toEqual([]);
});
