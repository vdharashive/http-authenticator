const request = require('request');
const nonce = require('nonce')();
const parseUri = require('drachtio-srf').parseUri;
const debug = require('debug')('jambonz:http-authenticator');

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

function digestChallenge(obj, logger) {
  let dynamicCallback;
  if (!logger) logger = {info: () => {}, error: () => {}};
  if (typeof obj === 'string') obj = {uri: obj};
  else if (typeof obj === 'function') dynamicCallback = obj;

  return async(req, res, next) => {
    let auth, uri, qs, body;
    let method = 'POST';

    const pieces = parseAuthHeader(req.get('Authorization'));
    const expires = req.registration ? req.registration.expires : null;
    const data = Object.assign({method: req.method, expires}, pieces);

    if (dynamicCallback) {
      const sipUri = parseUri(req.uri);
      try {
        const obj = await dynamicCallback(sipUri.host);
        if (!obj) {
          logger.debug(`jambonz-http-authenticator: Unknown realm ${sipUri.host}, rejecting with 403`);
          return res.send(403);
        }
        logger.debug({obj}, `jambonz-http-authenticator realm ${sipUri.host} auth details`);
        if (typeof obj === 'object') {
          uri = obj.uri || obj.url;
          if (obj.username && obj.password) auth = {username: obj.username, password: obj.password};
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
      if (obj.auth) auth = Object.assign({}, obj.auth);
    }

    // challenge requests without credentials
    if (!req.has('Authorization')) return respondChallenge(req, res);

    debug(`parsed authorization header: ${JSON.stringify(pieces)}`);
    const opts = Object.assign({
      uri,
      auth,
      method,
      json: true
    });
    if ('GET' === method) opts.qs = data;
    else opts.body = data;

    debug(`sending http request with ${JSON.stringify(opts)}`);
    request(opts, (err, response, body) => {
      if (err) {
        debug(`Error from calling auth callback: ${err}`);
        return next(err);
      }
      debug(`received ${response.statusCode} with body ${JSON.stringify(body)}`);
      if (response.statusCode !== 200) {
        debug(`auth callback returned a non-success response: ${response.statusCode}`);
        return res.send(500);
      }
      if (body.status != 'ok') {
        // TODO: deal with blacklist requests
        res.send(403);
      }

      // success
      req.authorization = {
        challengeResponse: pieces,
        grant: body
      };
      next();
    });
  };
}

module.exports = digestChallenge;
