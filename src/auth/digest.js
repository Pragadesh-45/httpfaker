const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const realm = process.env.DIGEST_REALM || 'httpfaker.org';
const opaque = process.env.DIGEST_OPAQUE || 'httpfaker-opaque-value';

let users = {
  'admin': 'password',
  'user': 'secret',
  'test': 'test123'
};

function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}

function H(data, algorithm = 'MD5') {
  if (algorithm === 'SHA-256') {
    return crypto.createHash('sha256').update(data).digest('hex');
  } else if (algorithm === 'SHA-512') {
    return crypto.createHash('sha512').update(data).digest('hex');
  } else {
    return crypto.createHash('md5').update(data).digest('hex');
  }
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
      // quoted string - improved regex to handle escaped quotes
      const quotedValue = header.match(/^"((?:[^"\\]|\\.)*)"/);
      if (quotedValue === null) {
        return false;
      }
      header = header.slice(quotedValue[0].length);
      value = quotedValue[1].replace(/\\(.)/g, '$1'); // unescape
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

// HA1 = H(A1) = H(username:realm:password)
function HA1(realm, username, password, algorithm = 'MD5') {
  if (!realm) realm = '';
  return H(Buffer.concat([
    Buffer.from(username, 'utf8'),
    Buffer.from(':', 'utf8'),
    Buffer.from(realm, 'utf8'),
    Buffer.from(':', 'utf8'),
    Buffer.from(password, 'utf8')
  ]), algorithm);
}

// HA2 = H(A2) = H(method:uri) for qop="auth" or qop not specified
// HA2 = H(A2) = H(method:uri:H(entity-body)) for qop="auth-int"
function HA2(credentials, request, algorithm = 'MD5') {
  const method = request.method;
  const uri = credentials.uri;
  const qop = credentials.qop;
  
  if (!qop || qop === 'auth') {
    return H(Buffer.concat([
      Buffer.from(method, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(uri, 'utf8')
    ]), algorithm);
  } else if (qop === 'auth-int') {
    const body = request.body || Buffer.alloc(0);
    const bodyHash = H(body, algorithm);
    return H(Buffer.concat([
      Buffer.from(method, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(uri, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(bodyHash, 'utf8')
    ]), algorithm);
  }
  throw new Error('Invalid qop value');
}

// Calculate digest response according to RFC 2617
function calculateResponse(credentials, password, request) {
  const algorithm = credentials.algorithm || 'MD5';
  const HA1_value = HA1(credentials.realm, credentials.username, password, algorithm);
  const HA2_value = HA2(credentials, request, algorithm);
  
  let response;
  if (!credentials.qop) {
    // RESPONSE = H(HA1:nonce:HA2)
    response = H(Buffer.concat([
      Buffer.from(HA1_value, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(credentials.nonce || '', 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(HA2_value, 'utf8')
    ]), algorithm);
  } else if (credentials.qop === 'auth' || credentials.qop === 'auth-int') {
    // RESPONSE = H(HA1:nonce:nonceCount:clientNonce:qop:HA2)
    if (!credentials.nonce || !credentials.nc || !credentials.cnonce || !credentials.qop) {
      throw new Error('Missing required qop parameters');
    }
    response = H(Buffer.concat([
      Buffer.from(HA1_value, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(credentials.nonce, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(credentials.nc, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(credentials.cnonce, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(credentials.qop, 'utf8'),
      Buffer.from(':', 'utf8'),
      Buffer.from(HA2_value, 'utf8')
    ]), algorithm);
  } else {
    throw new Error('Invalid qop value');
  }
  
  return response;
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
    console.log('Nonce mismatch - expected:', expectedNonce, 'got:', authinfo.nonce);
    return false;
  }

  // Use the URI from the authorization header as-is (client sends the correct URI)
  const requestUri = authinfo.uri;
  console.log('Using URI from auth header:', requestUri);

  // Add request body for auth-int
  const requestData = {
    method: request.method,
    uri: requestUri,
    body: request.body || Buffer.alloc(0)
  };

  try {
    const expectedResponse = calculateResponse(authinfo, password, requestData);
    console.log('Expected response:', expectedResponse);
    console.log('Client response:', authinfo.response);
    return expectedResponse === authinfo.response;
  } catch (error) {
    console.log('Authentication error:', error.message);
    return false;
  }
}

const sessionNonces = new Map();
const sessionTimestamps = new Map();

const authenticateDigest = (qop = 'auth', algorithm = 'MD5') => (req, res, next) => {
  let sessionId = req.headers['x-session-id'] || req.headers['x-nonce-id'];
  let authenticated = false;

  console.log('=== Digest Auth Debug ===');
  console.log('Request URL:', req.url);
  console.log('Request originalUrl:', req.originalUrl);
  console.log('Session ID from headers:', sessionId);
  console.log('Authorization header:', req.headers.authorization);

  if (req.headers.authorization) {
    // Parse the authorization header to get the nonce
    const authinfo = parseHeaderString(req.headers.authorization);
    if (authinfo && authinfo.nonce) {
      // Find session by nonce (since client doesn't send X-Session-ID)
      let foundSessionId = null;
      for (const [sid, nonce] of sessionNonces.entries()) {
        if (nonce === authinfo.nonce) {
          foundSessionId = sid;
          break;
        }
      }
      
      console.log('Found session ID for nonce:', foundSessionId);
      
      if (foundSessionId) {
        // Try each user
        for (const [username, password] of Object.entries(users)) {
          console.log(`Trying user: ${username}`);
          if (authenticate(req, req.headers.authorization, username, password, authinfo.nonce, qop)) {
            authenticated = true;
            req.user = username;
            console.log(`Authentication successful for user: ${username}`);
            break;
          }
        }
      } else {
        console.log('No session found for nonce:', authinfo.nonce);
      }
    }
  }

  if (!authenticated) {
    const nonce = generateNonce();
    // Use nonce as both the session ID and the nonce value
    sessionId = sessionId || nonce;
    sessionNonces.set(sessionId, nonce);
    sessionTimestamps.set(sessionId, Date.now());

    console.log('Generating new challenge with nonce:', nonce);
    console.log('Session ID:', sessionId);

    // Generate proper WWW-Authenticate header
    let header = `Digest realm="${realm}", nonce="${nonce}", opaque="${opaque}"`;
    
    if (algorithm && algorithm !== 'MD5') {
      header += `, algorithm=${algorithm}`;
    }
    
    if (qop && qop !== 'none') {
      if (qop === 'auth' || qop === 'auth-int') {
        header += `, qop="${qop}"`;
      } else {
        header += `, qop="auth,auth-int"`;
      }
    }
    
    res.status(401);
    res.setHeader('WWW-Authenticate', header);
    res.setHeader('X-Session-ID', sessionId);
    return res.json({
      message: 'Authentication required',
      sessionId: sessionId,
      nonce: nonce,
      qop: qop,
      algorithm: algorithm,
      users: Object.keys(users)
    });
  }

  next();
};

router.get('/:qop/:user/:passwd', (req, res) => {
  const { qop, user, passwd } = req.params;
  const algorithm = req.query.algorithm || 'MD5';

  if (!users[user]) {
    users[user] = passwd;
    console.log(`Auto-created user: ${user}`);
  } else if (users[user] !== passwd) {
    users[user] = passwd;
    console.log(`Updated password for user: ${user}`);
  }

  authenticateDigest(qop, algorithm)(req, res, () => {
    res.status(200).json({
      message: 'Access granted',
      authenticated: true,
      user: req.user,
      qop: qop,
      algorithm: algorithm,
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

// Add route for algorithm-specific testing
router.get('/:qop/:user/:passwd/:algorithm', (req, res) => {
  const { qop, user, passwd, algorithm } = req.params;

  if (!users[user]) {
    users[user] = passwd;
    console.log(`Auto-created user: ${user}`);
  } else if (users[user] !== passwd) {
    users[user] = passwd;
    console.log(`Updated password for user: ${user}`);
  }

  authenticateDigest(qop, algorithm)(req, res, () => {
    res.status(200).json({
      message: 'Access granted',
      authenticated: true,
      user: req.user,
      qop: qop,
      algorithm: algorithm,
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
  for (const [sessionId, timestamp] of sessionTimestamps.entries()) {
    if (now - timestamp > 300000) { // 5 minutes
      sessionNonces.delete(sessionId);
      sessionTimestamps.delete(sessionId);
    }
  }
}, 300000);

// Export functions for testing
module.exports = router;
module.exports.H = H;
module.exports.HA1 = HA1;
module.exports.HA2 = HA2;
module.exports.calculateResponse = calculateResponse;
module.exports.parseHeaderString = parseHeaderString;