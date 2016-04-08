var BasicStrategy = require('passport-http').BasicStrategy,
    OAuth2Strategy = require('passport-http-bearer').Strategy,
    $http = require('http-as-promised'),
    MD5 = require('md5'),
    Redis = require('then-redis');

function _fetchAndCacheUser(options, token, hashedToken) {
    return $http.get(options.infoURL + '?access_token=' + token,
        {
            json: true,
            error: false
        })
        .spread(function cacheValidResponse(res, body) {
            var user;

            if (!body || !body.agcoUUID || !body.expires_in) return false;

            // cache valid user
            user = {
                sub: body.agcoUUID,
                token: body
            };
            options.redis.multi();
            options.redis.set(hashedToken, JSON.stringify(user));
            options.redis.expire(hashedToken, body.expires_in);
            return options.redis.exec().then(function () { return user });
        });
}


function createBasicStrategy(options) {
    var redis =  Redis.createClient(options.redis);

    return new BasicStrategy(function(username, password, done) {
        var header = username + ':' + password,
            hashedHeader = basicKey(MD5(header)),
            URL = options.openAMBaseURL,
            infoURL = options.openAMInfoURL,
            scopes = options.scope.join(' ');

        return getRedis(redis, hashedHeader)
            .then(function(cachedUser) {
                if (!cachedUser) {

                    // use username and password to get a token
                    return $http.post(URL, {
                            form: {
                                client_id: options.client_id,
                                client_secret: options.client_secret,
                                grant_type: 'password',
                                username: username,
                                password: password,
                                scope: scopes
                            },
                            error: true,
                            json:true
                        })
                        .spread(function useTokentoGetAndCacheUser(res, body) {
                            if (!body || !body.access_token) return false;
                            return _fetchAndCacheUser({ infoURL: infoURL, redis: redis }, body.access_token, hashedHeader);
                        });
                }
                return JSON.parse(cachedUser);
            })
            .then(function returnUser(authedUser) {
                return done(null, authedUser);
            })
            .catch(function invalidate(err) {
                console.error('[BasicStrategy]:', err)
                return done(null, false)
            });
    });

}

function createOauth2Strategy(options) {
    var redis = Redis.createClient(options.redis);

    return new OAuth2Strategy(function verify(token, done) {
        var hashedToken = oauth2Key(MD5(token));

        return getRedis(redis, hashedToken)
            .then(function checkCache(cachedUser) {
                if (!cachedUser) return _fetchAndCacheUser({ infoURL: options.openAMInfoURL, redis: redis }, token, hashedToken);

                return JSON.parse(cachedUser);
            })
            .then(function returnUser(authedUser) {
                return done(null, authedUser);
            })
            .catch(function invalidateAllErrors(err) {
                console.error('[Oauth2Stragegy]:', err)
                return done(err, false);
            });

    });
}

function getRedis(redis, key) {
    return redis.get(key);
}

function basicKey(md5) {
    return md5 + "-basic";
}

function oauth2Key(md5) {
    return md5 + "-oauth2";
}

module.exports = {
    basicKey: basicKey,
    oauth2Key: oauth2Key,
    basic: createBasicStrategy,
    oauth2: createOauth2Strategy
};
