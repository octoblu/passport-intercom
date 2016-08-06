var util = require('util')
  , OAuth2Strategy = require('passport-oauth2').Strategy
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Intercom authentication strategy authenticates requests by delegating to
 * Intercom using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientId`      	your Intercom application's client id
 *   - `clientSecret`  	your Intercom application's client secret
 *   - `callbackURL`   	URL to which Intercom will redirect the user after granting authorization (optional of set in your Intercom Application
 *   - `grant_type`		Must be authorization_code
 *
 * Examples:
 *
 *     passport.use(new IntercomStrategy({
 *         client_id: '123-456-789',
 *         client_secret: 'shhh-its-a-secret'
 *         redirect_uri: 'https://www.example.net/auth/Intercom/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://app.intercom.io/oauth';
  options.tokenURL = options.tokenURL || 'https://api.intercom.io/auth/eagle/token';
  options.grant_type = options.grant_type || 'authorization_code';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'intercom';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Intercom.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `Intercom`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var authorization = 'Bearer ' + accessToken;///
  done(null, {})
  var headers = {
    'Authorization' : authorization
  };
  this._oauth2._request('GET', 'https://api.intercom.io/users', headers, '', '', function(err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {

      var intercomProfile = JSON.parse(body);

      var profile = {
        provider: 'intercom',
        id: intercomProfile.user_id,
        name: intercomProfile.name,
        email : intercomProfile.email,
        _intercomProfile: intercomProfile
      };

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
