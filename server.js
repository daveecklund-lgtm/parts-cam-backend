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
  GOOGLE_REFRESH_TOKEN, // set this once (see /auth/start output) so it survives restarts
  ANTHROPIC_API_KEY,  // for /ocr -- NEVER put this in the phone page, that file is public
  OCR_MODEL           // optional override, defaults below
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

// /ocr posts a base64 JPEG, so a JSON body parser is needed. Limit is generous
// enough for a ~1600px photo (base64 adds about a third).
app.use(express.json({ limit: '12mb' }));

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

// Read a part number off a photo with Claude vision.
// Body: { image: "data:image/jpeg;base64,..." }
// Returns: { candidates: [{ text, alternates: [..], confidence }] }
const OCR_PROMPT = [
  'This is a photo of an automotive part label, tag, or a number stamped into a part.',
  'Transcribe every distinct part number you can see.',
  '',
  'Rules:',
  '- Transcribe EXACTLY as printed, including dashes. Do not normalise, expand or tidy.',
  '- These are OEM part numbers (Ford, Caterpillar and similar). They mix letters and',
  '  digits freely, so you cannot infer a character from its neighbours.',
  '- Some characters are genuinely ambiguous in these fonts: 0/O, 1/I/L, 5/S, 8/B, 2/Z,',
  '  6/G, 7/T, 4/A. When you are not certain which one is printed, put your best reading',
  '  in "text" and add the OTHER full readings to "alternates". Include one alternate per',
  '  plausible combination, up to 8. This matters more than picking correctly.',
  '- Ignore dates, quantities, barcodes, prices, phone numbers and marketing text.',
  '- If you cannot read any part number, return an empty candidates array.',
  '',
  'Reply with JSON only, no other text:',
  '{"candidates":[{"text":"F67Z-7A095-BA","alternates":["F672-7A095-BA"],"confidence":"high"}]}'
].join('\n');

app.post('/ocr', async (req, res) => {
  if(req.headers['x-app-secret'] !== APP_SHARED_SECRET){
    return res.status(403).json({ error: 'forbidden' });
  }
  if(!ANTHROPIC_API_KEY){
    return res.status(400).json({ error: 'not_configured',
      message: 'Set ANTHROPIC_API_KEY in the Render environment to enable Claude OCR.' });
  }
  const image = (req.body && req.body.image) || '';
  const m = /^data:image\/(jpeg|jpg|png|webp);base64,(.+)$/i.exec(image);
  if(!m) return res.status(400).json({ error: 'bad_image', message: 'Expected a base64 data URL.' });
  const mediaType = 'image/' + (m[1].toLowerCase() === 'jpg' ? 'jpeg' : m[1].toLowerCase());

  try{
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: OCR_MODEL || 'claude-haiku-4-5',   // fast + cheap for a phone tag read (Dave's pick); override via OCR_MODEL
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mediaType, data: m[2] } },
            { type: 'text', text: OCR_PROMPT }
          ]
        }]
      })
    });
    const data = await r.json();
    if(!r.ok){
      const detail = (data && data.error && data.error.message) || ('HTTP ' + r.status);
      return res.status(502).json({ error: 'ocr_failed', message: detail });
    }
    const text = (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
    // The model is told to reply with JSON only; pull the object out defensively anyway.
    const j = /\{[\s\S]*\}/.exec(text);
    if(!j) return res.json({ candidates: [], raw: text });
    let parsed;
    try{ parsed = JSON.parse(j[0]); }
    catch(e){ return res.json({ candidates: [], raw: text }); }
    res.json({ candidates: Array.isArray(parsed.candidates) ? parsed.candidates : [] });
  }catch(e){
    res.status(500).json({ error: 'server_error', message: e.message });
  }
});

app.get('/', (req, res) => res.send('Parts Cam token server is running.'));

app.listen(PORT, () => console.log('Listening on ' + PORT));
