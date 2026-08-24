// Parts Cam token server (service-account version)
//
// Uses a Google service account instead of user OAuth. The server signs its own
// short-lived credentials with the service account's private key, so there are
// no refresh tokens, no 7-day expiry, no consent screen, and no sign-in ever.
//
// Setup:
//   1. In Google Cloud Console, create a JSON key for your service account.
//   2. Paste the ENTIRE contents of that JSON file into a Render environment
//      variable named GOOGLE_SERVICE_ACCOUNT_JSON.
//   3. In Google Drive, share your target folder with the service account's
//      email address (Editor access), then put that folder's ID in DRIVE_FOLDER_ID.

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const {
  GOOGLE_SERVICE_ACCOUNT_JSON, // full JSON key file contents
  APP_SHARED_SECRET,           // random string your app sends to prove it's yours
  ALLOWED_ORIGIN,              // e.g. https://daveecklund-lgtm.github.io
  DRIVE_FOLDER_ID              // ID of the Drive folder shared with the service account
} = process.env;

const SCOPE = 'https://www.googleapis.com/auth/drive';

let serviceAccount = null;
try{
  if(GOOGLE_SERVICE_ACCOUNT_JSON){
    serviceAccount = JSON.parse(GOOGLE_SERVICE_ACCOUNT_JSON);
  }
}catch(e){
  console.error('GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON:', e.message);
}

// Cache the access token so we're not re-signing on every single request
let cachedToken = null;
let cachedTokenExpiry = 0;

function base64url(input){
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Build and sign a JWT, then trade it with Google for an access token.
async function mintAccessToken(){
  if(!serviceAccount) throw new Error('Service account JSON not configured');

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = {
    iss: serviceAccount.client_email,
    scope: SCOPE,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };

  const unsigned = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(claims));
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const signature = signer
    .sign(serviceAccount.private_key, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const jwt = unsigned + '.' + signature;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    })
  });
  const data = await res.json();
  if(!data.access_token){
    throw new Error('Token exchange failed: ' + JSON.stringify(data));
  }
  cachedToken = data.access_token;
  cachedTokenExpiry = Date.now() + ((data.expires_in || 3600) - 120) * 1000;
  return cachedToken;
}

async function getAccessToken(){
  if(cachedToken && Date.now() < cachedTokenExpiry) return cachedToken;
  return mintAccessToken();
}

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', ALLOWED_ORIGIN || '*');
  res.header('Access-Control-Allow-Headers', 'x-app-secret, Content-Type');
  if(req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// The phone app calls this. Same contract as before, so the app needs no changes.
app.get('/token', async (req, res) => {
  if(req.headers['x-app-secret'] !== APP_SHARED_SECRET){
    return res.status(403).json({ error: 'forbidden' });
  }
  if(!serviceAccount){
    return res.status(500).json({
      error: 'not_configured',
      message: 'GOOGLE_SERVICE_ACCOUNT_JSON is missing or invalid'
    });
  }
  try{
    const token = await getAccessToken();
    res.json({
      access_token: token,
      expires_in: Math.max(60, Math.floor((cachedTokenExpiry - Date.now()) / 1000)),
      folder_id: DRIVE_FOLDER_ID || null
    });
  }catch(e){
    res.status(500).json({ error: 'refresh_failed', message: e.message });
  }
});

// Handy check: confirms config and shows which account to share your folder with.
app.get('/status', (req, res) => {
  res.json({
    service_account_configured: !!serviceAccount,
    service_account_email: serviceAccount ? serviceAccount.client_email : null,
    drive_folder_id_set: !!DRIVE_FOLDER_ID,
    note: 'Share your Drive folder with the service_account_email above (Editor access).'
  });
});

app.get('/', (req, res) => res.send('Parts Cam token server is running (service account mode).'));

app.listen(PORT, () => console.log('Listening on ' + PORT));
