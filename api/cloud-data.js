
const crypto = require('crypto');

function verifyAdminToken(token) {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret || typeof token !== 'string') return false;

  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(parts[0])
    .digest('base64url');

  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString('utf8')
    );

    return payload.role === 'admin' &&
      Number(payload.exp) > Math.floor(Date.now() / 1000);
  } catch (_) {
    return false;
  }
}

function same(a, b) {
  return JSON.stringify(a === undefined ? null : a) ===
    JSON.stringify(b === undefined ? null : b);
}

function emptyRecord() {
  return {
    users: {},
    requests: [],
    promoCodes: {},
    deletedPromos: [],
    bestDrop: null,
    liveDrops: []
  };
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Vary', 'Origin');

  if (req.method !== 'GET' && req.method !== 'PUT') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const origin = req.headers.origin;
  const host = req.headers.host;

  if (origin && host) {
    try {
      if (new URL(origin).host !== host) {
        return res.status(403).json({ error: 'Origin not allowed' });
      }
    } catch (_) {
      return res.status(403).json({ error: 'Invalid origin' });
    }
  }

  const binId = process.env.JSONBIN_BIN_ID;
  const masterKey = process.env.JSONBIN_MASTER_KEY;

  if (!binId || !masterKey) {
    return res.status(503).json({
      error: 'JSONBin environment variables are not configured'
    });
  }

  const url = `https://api.jsonbin.io/v3/b/${encodeURIComponent(binId)}`;

  const headers = {
    'X-Master-Key': masterKey,
    'Content-Type': 'application/json'
  };

  try {
    const read = await fetch(`${url}/latest`, {
      headers: { 'X-Master-Key': masterKey },
      cache: 'no-store'
    });

    if (!read.ok) {
      const detail = await read.text();

      return res.status(502).json({
        error: `JSONBin read failed: ${read.status}`,
        detail: detail.slice(0, 300)
      });
    }

    const latestJson = await read.json();

    const latest =
      latestJson && latestJson.record &&
      typeof latestJson.record === 'object'
        ? latestJson.record
        : emptyRecord();

    if (req.method === 'GET') {
      return res.status(200).json({ record: latest });
    }

    const incoming = req.body;

    if (!incoming || typeof incoming !== 'object' ||
        Array.isArray(incoming)) {
      return res.status(400).json({
        error: 'Expected a JSON object'
      });
    }

    const admin = verifyAdminToken(req.headers['x-admin-token']);

    const adminFields = [
      'siteContent',
      'fuseSettings',
      'promoCodes',
      'deletedPromos'
    ];

    const changesAdminFields = adminFields.some(
      key => !same(incoming[key], latest[key])
    );

    if (changesAdminFields && !admin) {
      return res.status(403).json({
        error: 'Admin authentication required for shared site settings'
      });
    }

    const merged = { ...latest, ...incoming };

    merged.users = {
      ...(latest.users || {}),
      ...(incoming.users || {})
    };

    if (!admin) {
      for (const key of adminFields) {
        merged[key] = latest[key];
      }
    }

    const today = new Date().toISOString().slice(0, 10);

    const oldDrop =
      latest.bestDrop &&
      (!latest.bestDrop.date || latest.bestDrop.date === today)
        ? latest.bestDrop
        : null;

    const newDrop =
      incoming.bestDrop &&
      (!incoming.bestDrop.date || incoming.bestDrop.date === today)
        ? incoming.bestDrop
        : null;

    const oldPrice = oldDrop && oldDrop.item
      ? Number(oldDrop.item.price) || 0
      : 0;

    const newPrice = newDrop && newDrop.item
      ? Number(newDrop.item.price) || 0
      : 0;

    merged.bestDrop = newPrice >= oldPrice
      ? (newDrop || oldDrop)
      : oldDrop;

    const write = await fetch(url, {
      method: 'PUT',
      headers,
      body: JSON.stringify(merged)
    });

    if (!write.ok) {
      const detail = await write.text();

      return res.status(502).json({
        error: `JSONBin write failed: ${write.status}`,
        detail: detail.slice(0, 300)
      });
    }

    const saved = await write.json();

    return res.status(200).json({
      record: saved && saved.record ? saved.record : merged
    });

  } catch (error) {
    console.error('cloud-data error:', error);

    return res.status(500).json({
      error: 'Cloud service error'
    });
  }
};
