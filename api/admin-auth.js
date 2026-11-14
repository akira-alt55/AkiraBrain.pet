const crypto = require('crypto');

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const expected = process.env.ADMIN_PASSWORD;

  if (!expected) {
    return res.status(503).json({
      error: 'ADMIN_PASSWORD is not configured'
    });
  }

  const password = req.body && req.body.password;

  if (!safeEqual(password, expected)) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const expires = Math.floor(Date.now() / 1000) + 60 * 60 * 8;

  const payload = Buffer.from(JSON.stringify({
    role: 'admin',
    exp: expires
  })).toString('base64url');

  const signature = crypto
    .createHmac('sha256', expected)
    .update(payload)
    .digest('base64url');

  return res.status(200).json({
    token: `${payload}.${signature}`,
    expires
  });
};
