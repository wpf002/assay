import express from 'express';
import { issueKeyPair, token, legacyDigest } from './keys.js';

const app = express();

app.post('/v1/tokens', (req, res) => {
  const { publicKey } = issueKeyPair();
  res.json({ token: token({ sub: 'u' }, 'secret'), publicKey: String(publicKey) });
});

app.get('/v1/etag', (req, res) => {
  res.json({ etag: legacyDigest(String(req.query['v'])) });
});

app.listen(3000);
