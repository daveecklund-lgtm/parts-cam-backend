// Parts Cam token server
// Holds a Google refresh token and exchanges it for fresh access tokens on
// request, so the phone app never has to show a sign-in popup.

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  REDIRECT_URI,       // e.g. https://your-app.onrender.com/auth/callback
  APP_SHARED_SECRET,  // a random string only your app knows, to protect /token
  ALLOWED_ORIGIN,     // e.g. https://daveecklund-lgtm.github.io
  GOOGLE_REFRESH_TOKEN // set this once (see /auth/start output) so it survives restarts
} = process.env;

const TOKEN_FILE = path.join(__dirname, 'refresh_token.json');

function saveRefreshToken(token){
  // Best-effort local cache. On hosts with ephemeral disks (Render free tier) this
  // is wiped on restart — which is why GOOGLE_REFRESH_TOKEN env var is preferred.
  try{
    fs.writeFileSync(TOKEN_FILE, JSON.stringify({ refresh_token: token }));
  }catch(e){
    console.log('Could not write token file (ephemeral disk?):', e.message);
  }
}
function loadRefreshToken(){
  // Env var wins — it persists across restarts and redeploys.
  if(GOOGLE_REFRESH_TOKEN) return GOOGLE_REFRESH_TOKEN;
  try{
    return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')).refresh_token;
  }catch(e){
    return null;
  }
}

// CORS: only allow your GitHub Pages app to call this server
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', ALLOWED_ORIGIN || '*');
  res.header('Access-Control-Allow-Headers', 'x-app-secret, Content-Type');
  if(req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Step 1 (one-time, done by you in a browser): kicks off Google's consent screen
app.get('/auth/start', (req, res) => {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/drive.file',
    access_type: 'offline',   // required to get a refresh token
    prompt: 'consent'         // required to force a refresh token every time
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

// Step 2: Google redirects back here with a one-time code — exchange it for tokens
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  if(!code) return res.status(400).send('Missing code');
  try{
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const data = await tokenRes.json();
    if(!data.refresh_token){
      return res.status(500).send(
        'No refresh_token in response. Go to myaccount.google.com/permissions, ' +
        'remove access for this app, then try /auth/start again. ' +
        'Raw response: ' + JSON.stringify(data)
      );
    }
    saveRefreshToken(data.refresh_token);
    res.send(
      '<html><body style="font-family:system-ui;max-width:640px;margin:40px auto;line-height:1.6">' +
      '<h2>Connected to Google Drive</h2>' +
      '<p><b>One more step.</b> This host wipes local files on restart, ' +
      'so save the token below as an environment variable:</p>' +
      '<ol><li>In Render: your service &rarr; Environment &rarr; Add Environment Variable</li>' +
      '<li>Key: <code>GOOGLE_REFRESH_TOKEN</code></li>' +
      '<li>Value: copy the string below</li>' +
      '<li>Save (Render redeploys automatically)</li></ol>' +
      '<p style="word-break:break-all;background:#f2f2f2;padding:12px;border-radius:6px;font-family:monospace">' +
      data.refresh_token + '</p>' +
      '<p style="color:#a00"><b>Treat this like a password</b> &mdash; it grants access to your Drive. ' +
      'Do not share or post it. Close this tab once saved.</p>' +
      '</body></html>'
    );
  }catch(e){
    res.status(500).send('Error exchanging code: ' + e.message);
  }
});

// Step 3 (called automatically by the app): get a fresh access token
app.get('/token', async (req, res) => {
  if(req.headers['x-app-secret'] !== APP_SHARED_SECRET){
    return res.status(403).json({ error: 'forbidden' });
  }
  const refreshToken = loadRefreshToken();
  if(!refreshToken){
    return res.status(400).json({ error: 'not_connected', message: 'Visit /auth/start once to connect Drive first.' });
  }
  try{
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        refresh_token: refreshToken,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        grant_type: 'refresh_token'
      })
    });
    const data = await tokenRes.json();
    if(!data.access_token){
      return res.status(500).json({ error: 'refresh_failed', detail: data });
    }
    res.json({ access_token: data.access_token, expires_in: data.expires_in });
  }catch(e){
    res.status(500).json({ error: 'server_error', message: e.message });
  }
});

app.get('/', (req, res) => res.send('Parts Cam token server is running.'));

app.listen(PORT, () => console.log('Listening on ' + PORT));
