'use strict';
// No external assets or persistent browser storage of claims and secrets.
(() => {
  const $ = id => document.getElementById(id);
  const form = $('first-run-form');
  if (!form) return;
  let step = 0, claim = '', flowId = '', recipientHint = '';
  const stages = ['Authorize', 'Company email', 'Sender OTP', 'Admin email', 'Admin OTP', 'Password'];
  const titles = ['Authorize this installation', 'Connect company email', 'Verify sender delivery', 'Register your email', 'Verify your email', 'Create administrator'];
  const descriptions = [
    'Setup created a one-time code in a protected file. Open it locally as a Windows administrator and paste the code below.',
    'Use an existing company no-reply mailbox or approved SMTP relay. A verification code is sent to a mailbox you can read.',
    'Enter the six-digit code delivered through the configured sender. SMTP acceptance alone does not prove receipt.',
    'Enter the address of the first administrator. We will send a separate registration code.',
    'Enter the six-digit registration code. Your password cannot be created until this email is verified.',
    'Choose your username and a strong password. Email OTP will be enabled for subsequent local sign-ins.'
  ];
  const fields = [
    '<p class="first-run-path"><code>C:\\ProgramData\\GatewayCoreYarp\\ControlPlane\\first-run-code.txt</code></p><label>Installation setup code<input name="setupCode" type="password" required minlength="64" maxlength="64" autocomplete="off" spellcheck="false"></label>',
    '<label>Company sender email<input name="from" type="email" placeholder="noreply@company.com" required maxlength="254"></label><label>Verification inbox (must receive email)<input name="email" type="email" placeholder="it-admin@company.com" required maxlength="254"></label><div class="first-run-pair"><label>SMTP hostname<input name="host" placeholder="smtp.company.com" required maxlength="255"></label><label>Port<input name="port" type="number" min="1" max="65535" value="587" required></label></div><label>Authentication<select name="authMode"><option value="password">Approved relay / app password</option><option value="google-oauth">Google OAuth2</option><option value="microsoft-oauth">Microsoft delegated OAuth2</option><option value="microsoft-app">Microsoft application OAuth2</option></select></label><label>SMTP username (optional for approved relay)<input name="username" maxlength="254" autocomplete="off"></label><label id="first-run-smtp-password">SMTP app password<input type="password" name="smtpPassword" maxlength="4096" autocomplete="off"></label><div id="first-run-oauth" class="first-run-fields" hidden><label>OAuth client ID<input name="oauthClientId" maxlength="256" autocomplete="off"></label><label>OAuth tenant (Microsoft)<input name="oauthTenant" maxlength="100" autocomplete="off"></label><label>OAuth client secret<input name="oauthClientSecret" type="password" maxlength="4096" autocomplete="off"></label><label id="first-run-refresh">OAuth refresh token<input name="oauthRefreshToken" type="password" maxlength="16384" autocomplete="off"></label></div><p class="subtle">STARTTLS and trusted server certificates are required. Port 465 is not supported. Do not enter your personal mailbox password.</p>',
    '<label>Sender verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>',
    '<label>Administrator email<input name="email" type="email" placeholder="admin@company.com" maxlength="254" required></label>',
    '<label>Administrator verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>',
    '<label>Username<input name="username" autocomplete="username" pattern="[A-Za-z0-9_.\\-]{3,40}" required minlength="3" maxlength="40"></label><label>Password (at least 16 characters)<input name="password" type="password" autocomplete="new-password" minlength="16" maxlength="256" required></label><label>Confirm password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="16" maxlength="256" required></label>'
  ];
  const labels = ['Continue', 'Send sender verification code', 'Verify sender', 'Send registration code', 'Verify email', 'Create administrator'];
  function render() {
    $('first-run-step').textContent = 'STEP ' + (step + 1) + ' OF ' + stages.length;
    $('first-run-title').textContent = titles[step];
    $('first-run-description').textContent = descriptions[step] + ((step === 2 || step === 4) && recipientHint ? ' Sent to ' + recipientHint + '.' : '');
    $('first-run-progress').innerHTML = stages.map((s, i) => '<span class="' + (i < step ? 'complete' : i === step ? 'current' : '') + '"' + (i === step ? ' aria-current="step"' : '') + '>' + (i + 1) + '. ' + s + '</span>').join('');
    $('first-run-fields').innerHTML = fields[step];
    $('first-run-submit').textContent = labels[step];
    $('first-run-restart').hidden = step === 0;
    $('first-run-message').textContent = '';
    if (step === 1) {
      const mode = form.elements.namedItem('authMode');
      const update = () => {
        const oauth = mode.value !== 'password';
        $('first-run-oauth').hidden = !oauth;
        $('first-run-smtp-password').hidden = oauth;
        $('first-run-refresh').hidden = mode.value === 'microsoft-app';
      };
      mode.addEventListener('change', update);
      update();
    }
    if (!$('first-run-screen').hidden) $('first-run-fields').querySelector('input')?.focus();
  }
  $('first-run-restart').addEventListener('click', () => {
    if ($('first-run-submit').disabled) return;
    claim = ''; flowId = ''; recipientHint = ''; step = 0; render();
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = $('first-run-submit');
    if (submit.disabled) return;
    const values = new FormData(form);
    const val = key => String(values.get(key) || '');
    const actions = ['unlock', 'sender', 'verify-sender', 'administrator', 'verify-admin', 'finish'];
    if (step === 5 && val('password') !== val('confirmPassword')) {
      $('first-run-message').textContent = 'Passwords do not match.'; return;
    }
    const body = { action: actions[step], setupCode: step === 0 ? val('setupCode').trim() : claim, flowId };
    if (step === 1) {
      body.email = val('email').trim();
      body.mail = { enabled: true, host: val('host').trim(), port: Number(val('port')), from: val('from').trim(),
        username: val('username').trim(), password: val('smtpPassword'), startTls: true, authMode: val('authMode'),
        oAuthClientId: val('oauthClientId').trim(), oAuthTenant: val('oauthTenant').trim(),
        oAuthClientSecret: val('oauthClientSecret'), oAuthRefreshToken: val('oauthRefreshToken') };
    } else if (step === 2 || step === 4) body.code = val('code').trim();
    else if (step === 3) body.email = val('email').trim();
    else if (step === 5) { body.username = val('username').trim(); body.password = val('password'); }
    submit.disabled = true; form.setAttribute('aria-busy','true');
    $('first-run-message').textContent = '';
    try {
      const response = await fetch('/admin/api/bootstrap/setup', {
        method:'POST', credentials:'same-origin', cache:'no-store',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw Error(result.error || (response.status === 429 ? 'Too many setup requests. Try again after the rate limit resets.' : 'Setup request failed.'));
      if (step === 0) { if (!result.authorized) throw Error('Setup authorization failed.'); claim = body.setupCode; }
      if (step === 1 || step === 3) { if (!result.flowId) throw Error('Verification delivery was not confirmed.'); flowId = result.flowId; recipientHint = result.emailHint || ''; }
      if ((step === 2 || step === 4) && !result.verified) throw Error('Verification did not complete.');
      if (step === 5) {
        if (!result.authenticated) throw Error('Account creation was not confirmed.');
        claim = ''; flowId = ''; recipientHint = '';
        form.reset(); $('first-run-fields').textContent = ''; location.reload(); return;
      }
      step++; render();
    } catch (error) { $('first-run-message').textContent = String(error.message || error); }
    finally { submit.disabled = false; form.removeAttribute('aria-busy'); }
  });
  render();
})();
