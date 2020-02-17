const nonce = require('nonce')();
const parseUri = require('drachtio-srf').parseUri;
const noopLogger = {info: () => {}, error: () => {}};
const bent = require('bent');
const qs = require('qs');
const debug = require('debug')('jambonz:http-authenticator');

const toBase64 = (str) => Buffer.from(str || '', 'utf8').toString('base64');

function basicAuth(username, password) {
  if (!username || !password) return {};
  const creds = `${username}:${password || ''}`;
  const header = `Basic ${toBase64(creds)}`;
  return {Authorization: header};
}

function parseAuthHeader(hdrValue) {
  const pieces = { scheme: 'digest'} ;
  ['username', 'realm', 'nonce', 'uri', 'algorithm', 'response', 'qop', 'nc', 'cnonce', 'opaque']
    .forEach((tok) => {
      const re = new RegExp(`[,\\s]{1}${tok}="?(.+?)[",]`) ;
      const arr = re.exec(hdrValue) ;
      if (arr) {
        pieces[tok] = arr[1];
        if (pieces[tok] && pieces[tok] === '"') pieces[tok] = '';
      }
    }) ;

  pieces.algorithm = pieces.algorithm || 'MD5' ;

  // this is kind of lame...nc= (or qop=) at the end fails the regex above,
  // should figure out how to fix that
  if (!pieces.nc && /nc=/.test(hdrValue)) {
    const arr = /nc=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.nc = arr[1];
    }
  }
  if (!pieces.qop && /qop=/.test(hdrValue)) {
    const arr = /qop=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.qop = arr[1];
    }
  }

  // check mandatory fields
  ['username', 'realm', 'nonce', 'uri', 'response'].forEach((tok) => {
    if (!pieces[tok]) throw new Error(`missing authorization component: ${tok}`);
  }) ;
  debug(`parsed header: ${JSON.stringify(pieces)}`);
  return pieces ;
}

function respondChallenge(req, res) {
  const nonceValue = nonce();
  const uri = parseUri(req.uri);
  const headers = {
    'WWW-Authenticate': `Digest realm="${uri.host}", algorithm=MD5, qop="auth", nonce="${nonceValue}"`
  };
  debug('sending a 401 challenge');
  res.send(401, {headers});
}

function digestChallenge(obj, logger, opts) {
  let dynamicCallback;
  opts = opts || {};
  if (logger && typeof logger.info !== 'function') {
    opts = logger;
    logger = noopLogger;
  }
  if (!logger) logger = noopLogger;
  if (typeof obj === 'string') obj = {uri: obj};
  else if (typeof obj === 'function') dynamicCallback = obj;

  return async(req, res, next) => {
    let headers = {}, uri;
    let method = 'POST';

    if (dynamicCallback) {
      const sipUri = parseUri(req.uri);
      try {
        const obj = await dynamicCallback(sipUri.host);
        if (!obj) {
          logger.debug(`jambonz-http-authenticator: Unknown realm ${sipUri.host}, rejecting with 403`);
          return res.send(403, {
            headers: {
              'X-Reason': obj.blacklistUnknownRealms ?
                `detected potential spammer from ${req.source_address}:${req.source_port}` :
                'Unknown or invalid realm'
            }
          });
        }
        logger.debug({obj}, `jambonz-http-authenticator realm ${sipUri.host} auth details`);
        if (typeof obj === 'object') {
          uri = obj.uri || obj.url;
          if (obj.username && obj.password) headers = basicAuth(obj.username, obj.password);
          if (obj.method) method = obj.method.toUpperCase();
        }
        else uri = obj;
      } catch (err) {
        logger.error(`Error ${err}, rejecting with 403`);
        return next(err);
      }
    }
    else {
      uri = obj.uri || obj.url;
      if (obj.auth) headers = basicAuth(obj.auth.username, obj.auth.password);
    }

    // challenge requests without credentials
    if (!req.has('Authorization')) return respondChallenge(req, res);
    const pieces = parseAuthHeader(req.get('Authorization'));
    const expires = req.registration ? req.registration.expires : null;
    const data = Object.assign({method: req.method, expires}, pieces);

    debug(`parsed authorization header: ${JSON.stringify(pieces)}`);

    let body = null;
    if ('GET' === method) {
      const str = qs.stringify(data);
      uri = `${uri}?${str}`;
    }
    else {
      body = data;
    }

    const request = bent('json', 200, method, headers);
    try {
      const json = await request(uri, body, headers);
      if (json.status !== 'ok') {
        res.send(403, {headers: {
          'X-Reason': json.blacklist === true ?
            `detected potential spammer from ${req.source_address}:${req.source_port}` :
            'Invalid credentials'
        }});
      }
      req.authorization = {
        challengeResponse: pieces,
        grant: json
      };
      next();
    }
    catch (err) {
      debug(`Error from calling auth callback: ${err}`);
      return next(err);
    }
  };
}

module.exports = digestChallenge;
