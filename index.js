var ERR = require('async-stacktrace');
var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var request = require('request');

// var settings = require('ep_etherpad-lite/node/utils/Settings').ep_oauth2;
var passport = require('passport');
var OAuth2Strategy = require('passport-oauth2').Strategy;

// Environment Variables
var authorizationURL = process.env['EP_OAUTH2_AUTHORIZATION_URL'] || settings.users.oauth2.authorizationURL;
var tokenURL = process.env['EP_OAUTH2_TOKEN_URL'] || settings.users.oauth2.tokenURL;
var clientID = process.env['EP_OAUTH2_CLIENT_ID'] || settings.users.oauth2.clientID;
var clientSecret = process.env['EP_OAUTH2_CLIENT_SECRET'] || settings.users.oauth2.clientSecret;
var publicURL = process.env['EP_OAUTH2_PUBLIC_URL'] || settings.users.oauth2.publicURL;
var userinfoURL = process.env['EP_OAUTH2_USERINFO_URL'] || settings.users.oauth2.userinfoURL;
var usernameKey = process.env['EP_OAUTH2_USERNAME_KEY'] || settings.users.oauth2.usernameKey;
var idKey = process.env['EP_OAUTH2_USERID_KEY'] || settings.users.oauth2.useridKey;
var scope = process.env['EP_OAUTH2_SCOPE'] || settings.users.oauth2.scope;
var proxy = process.env['EP_OAUTH2_PROXY'] || settings.users.oauth2.proxy;
var state = process.env['EP_OAUTH2_STATE'] || settings.users.oauth2.state;

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

const ep = (endpoint) => `/ep_oauth2/${endpoint}`;
const endpointUrl = (endpoint) => new URL(ep(endpoint).substring(1), publicURL).toString();

function setUsername(token, username) {
  console.debug('oauth2.setUsername: getting authorid for token %s', token, username);
  authorManager.getAuthor4Token(token)
    .then((author) => {
      console.debug('oauth2.setUsername: have authorid %s, setting username to "%s"', author, username);
      authorManager.setAuthorName(author, username);
    })
    .catch((err) => {
      console.debug('oauth2.setUsername: could not get authorid for token %s', token);
      console.error(err);
    });
  return;
}

exports.expressConfigure = function(hook_name, context) {
  console.log('oauth2-expressConfigure');
  passport.use('hbp', new OAuth2Strategy({
    authorizationURL: authorizationURL,
    tokenURL: tokenURL,
    clientID: clientID,
    clientSecret: clientSecret,
    callbackURL: endpointUrl('callback'),
    scope: scope,
    proxy: proxy,
    state: state
  }, function(accessToken, refreshToken, profile, cb) {
    request.get({
      url: userinfoURL,
      auth: {
        bearer: accessToken
      },
      json: true
    }, function (error, response, data) {
      if (error) {
        return cb(error);
      }
      data.token = {
        type: 'bearer',
        accessToken: accessToken,
        refreshToken: refreshToken
      };
      authorManager.createAuthorIfNotExistsFor(data[idKey], data[usernameKey])
        .then((author) => {
          data.authorId = author.authorID;
          cb(null, data);
        })
        .catch((err) => cb(err));
    });
  }));
  var app = context.app;
  app.use(passport.initialize());
  app.use(passport.session());
}

exports.expressCreateServer = function (hook_name, context) {
  console.info('oauth2-expressCreateServer');
  var app = context.app;
  app.get(
    ep('callback'),
    (req, res, next) => {
      req.epSession = req.session;
      next();
    },
    passport.authenticate('hbp', {
      failureRedirect: ep('authfailure'),
    }),
    (req, res) => {
      req.session.ep_oauth2 = req.epSession.ep_oauth2;
      const oauth2Session = req.session.ep_oauth2 || {};
      oauth2Session.user = req.user;
      delete req.session.user;
      res.redirect(303, oauth2Session.next || publicURL);
      delete oauth2Session.next;
    }
  );
  app.get(
    ep('login'),
    passport.authenticate('hbp', {
      failureRedirect: ep('authfailure')
    })
  );
  app.get(ep('logout'), (req, res, next) => {
    console.debug(`Processing ${req.url}`);
    req.session.destroy(() => res.redirect(303, publicURL));
  });
  app.get(ep('authfailure'), function(req, res) {
    res.send("<em>Authentication Failed</em>");
  });
}

exports.authenticate = function(hook_name, context) {
  console.info('oauth2-authenticate from ->', context.req.url);
  const {req, res, users} = context;
  const {ep_oauth2: {user} = {}} = req.session;
  if (!user) {
    delete req.session.ep_oauth2;
    return;
  }
  // Successfully authenticated.
  console.info('Successfully authenticated user with userinfo:', user);
  req.session.user = user;
  console.debug('User properties:', req.session.user);
  return true;
}

exports.authnFailure = (hookName, {req, res}) => {
  // Reference from: https://github.com/ether/ep_openid_connect/blob/main/index.js
  // Normally the user is redirected to the login page which would then redirect the user back once
  // authenticated. For non-GET requests, send a 401 instead because users can't be redirected back.
  // Also send a 401 if an Authorization header is present to facilitate API error handling.
  //
  // 401 is the status that most closely matches the desired semantics. However, RFC7235 section
  // 3.1 says, "The server generating a 401 response MUST send a WWW-Authenticate header field
  // containing at least one challenge applicable to the target resource." Etherpad uses a token
  // (signed session identifier) transmitted via cookie for authentication, but there is no
  // standard authentication scheme name for that. So we use a non-standard name here.
  //
  // We could theoretically implement Bearer authorization (RFC6750), but it's unclear to me how
  // to do this correctly and securely:
  //   * The userinfo endpoint is meant for the OAuth client, not the resource server, so it
  //     shouldn't be used to look up claims.
  //   * In general, access tokens might be opaque (not JWTs) so we can't get claims by parsing
  //     them.
  //   * The token introspection endpoint should return scope and subject (I think?), but probably
  //     not claims.
  //   * If claims can't be used to convey access level, how is it conveyed? Scope? Resource
  //     indicators (RFC8707)?
  //   * How is intended audience checked? Or is introspection guaranteed to do that for us?
  //   * Should tokens be limited to a particular pad?
  //   * Bearer tokens are only meant to convey authorization; authentication is handled by the
  //     authorization server. Should Bearer tokens be processed during the authorize hook?
  //   * How should bearer authentication interact with authorization plugins?
  //   * How should bearer authentication interact with plugins that add new endpoints?
  //   * Would we have to implement our own OAuth server to issue access tokens?
  res.header('WWW-Authenticate', 'Etherpad');
  if (!['GET', 'HEAD'].includes(req.method) || req.headers.authorization) {
    res.status(401).end();
    return true;
  }
  if (req.session.ep_oauth2 == null) req.session.ep_oauth2 = {};
  req.session.ep_oauth2.next = new URL(req.url.slice(1), publicURL).toString();
  res.redirect(303, endpointUrl('login'));
  return true;
};

exports.preAuthorize = (hookName, {req}) => {
  if (req.path.startsWith(ep(''))) return true;
  return;
};

exports.handleMessage = function(hook_name, context, cb) {
  console.debug("oauth2.handleMessage");
  if ( context.message.type == "CLIENT_READY" ) {
    if (!context.message.token) {
      console.debug('oauth2.handleMessage: intercepted CLIENT_READY message has no token!');
    } else {
      var client_id = context.client.id;
      if ('user' in context.client.client.request.session) {
        var displayName = context.client.client.request.session.user[usernameKey];
        console.debug('oauth2.handleMessage: intercepted CLIENT_READY message for client_id = %s, setting username for token %s to %s', client_id, context.message.token, displayName);
        setUsername(context.message.token, displayName);
      }
      else {
        console.debug('oauth2.handleMessage: intercepted CLIENT_READY but user does have displayName !');
      }
    }
  } else if ( context.message.type == "COLLABROOM" && context.message.data.type == "USERINFO_UPDATE" ) {
    console.debug('oauth2.handleMessage: intercepted USERINFO_UPDATE and dropping it!');
    return cb([null]);
  }
  return cb([context.message]);
};
