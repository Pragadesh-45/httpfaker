const express = require('express');
const crypto = require('crypto');
const router = express.Router();


const realm = 'httpfaker.org';
const opaque = 'httpfaker-opaque-value';


let users = {
  'admin': 'password',
  'user': 'secret',
  'test': 'test123'
};


function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}

function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

function parseHeaderString(header) {
  const authtype = header.match(/^(\w+)\s+/);
  if (authtype === null) {
    return false;
  }
  if (authtype[1].toLowerCase() !== "digest") {
    return false;
  }
  header = header.slice(authtype[1].length);

  const dict = {};
  let first = true;
  while (header.length > 0) {
    // eat whitespace and comma
    if (first) {
      first = false;
    } else {
      if (header[0] !== ",") {
        return false;
      }
      header = header.slice(1);
    }
    header = header.trimLeft();

    // parse key
    const key = header.match(/^\w+/);
    if (key === null) {
      return false;
    }
    const keyValue = key[0];
    header = header.slice(keyValue.length);

    // parse equals
    const eq = header.match(/^\s*=\s*/);
    if (eq === null) {
      return false;
    }
    header = header.slice(eq[0].length);

    // parse value
    let value;
    if (header[0] === "\"") {
      // quoted string
      const quotedValue = header.match(/^"([^"\\\r\n]*(?:\\.[^"\\\r\n]*)*)"/);
      if (quotedValue === null) {
        return false;
      }
      header = header.slice(quotedValue[0].length);
      value = quotedValue[1];
    } else {
      // unquoted string
      const unquotedValue = header.match(/^[^\s,]+/);
      if (unquotedValue === null) {
        return false;
      }
      header = header.slice(unquotedValue[0].length);
      value = unquotedValue[0];
    }
    dict[keyValue] = value;

    // eat whitespace
    header = header.trimLeft();
  }
  return dict;
}

function authenticate(request, header, username, password, expectedNonce, qop) {
  const authinfo = parseHeaderString(header);
  if (authinfo === false) {
    console.log('Failed to parse header');
    return false;
  }

  console.log('Parsed auth info:', authinfo);

  if (authinfo.username !== username) {
    console.log('Username mismatch');
    return false;
  }

  if (authinfo.nonce !== expectedNonce) {
    console.log('Nonce mismatch');
    return false;
  }

  const a1 = authinfo.username + ":" + authinfo.realm + ":" + password;
  console.log('A1:', a1);

  const a2 = request.method + ":" + authinfo.uri;
  console.log('A2:', a2);

  let digest;
  if (!qop || qop === 'none') {
    digest = md5(md5(a1) + ":" + authinfo.nonce + ":" + md5(a2));
  } else {
    digest = md5(md5(a1) + ":" + authinfo.nonce + ":" + authinfo.nc + ":" + authinfo.cnonce + ":" + qop + ":" + md5(a2));
  }

  console.log('Expected digest:', digest);
  console.log('Client response:', authinfo.response);

  return digest === authinfo.response;
}

const sessionNonces = new Map();

const authenticateDigest = (qop = 'auth') => (req, res, next) => {
  const sessionId = req.headers['x-session-id'] || req.ip;
  let authenticated = false;

  if (req.headers.authorization) {
    const expectedNonce = sessionNonces.get(sessionId);
    if (expectedNonce) {
      // Try each user
      for (const [username, password] of Object.entries(users)) {
        if (authenticate(req, req.headers.authorization, username, password, expectedNonce, qop)) {
          authenticated = true;
          req.user = username;
          break;
        }
      }
    }
  }

  if (!authenticated) {
    const nonce = generateNonce();
    sessionNonces.set(sessionId, nonce);

    const qopValue = qop === 'none' ? '' : `, qop="${qop}"`;
    const header = `Digest realm="${realm}"${qopValue}, nonce="${nonce}", opaque="${opaque}"`;
    res.status(401);
    res.setHeader('WWW-Authenticate', header);
    res.setHeader('X-Session-ID', sessionId);
    return res.json({
      message: 'Authentication required',
      sessionId: sessionId,
      qop: qop,
      users: Object.keys(users)
    });
  }

  next();
};

router.get('/:qop/:user/:passwd', (req, res) => {
  const { qop, user, passwd } = req.params;

  if (!users[user]) {
    users[user] = passwd;
    console.log(`Auto-created user: ${user}`);
  } else if (users[user] !== passwd) {
    users[user] = passwd;
    console.log(`Updated password for user: ${user}`);
  }

  authenticateDigest(qop)(req, res, () => {
    res.status(200).json({
      message: 'Access granted',
      user: req.user,
      qop: qop,
      data: {
        name: 'httpfaker',
        version: '0.2.0',
        features: ['digest-auth', 'bearer-auth', 'oauth2'],
        timestamp: new Date().toISOString(),
        currentUsers: Object.keys(users)
      }
    });
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [sessionId, timestamp] of sessionNonces.entries()) {
    if (now - timestamp > 300000) { // 5 minutes
      sessionNonces.delete(sessionId);
    }
  }
}, 300000);

module.exports = router;