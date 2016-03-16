var BasicStrategy = require('passport-http').BasicStrategy,
    OAuth2Strategy = require('passport-http-bearer').Strategy,
    $http = require('http-as-promised'),
    _ = require('lodash'),
    MD5 = require('md5'),
    promise = require('bluebird'),
    Redis = require('then-redis');

function createBasicStrategy(options) {
    var redis =  Redis.createClient(options.redis);

    return new BasicStrategy(function(username, password, done) {
        var header = username + ':' + password,
            hashedHeader = basicKey(MD5(header)),
            URL = options.openAMBaseURL,
            infoURL = options.openAMInfoURL,
            scopes = options.scope.join(' ');

        return getRedis(redis, hashedHeader)
            .then(function(tokenInfo) {
                if (tokenInfo) return done(null, JSON.parse(tokenInfo));
                return postToken()
                    .spread(getandCacheTokenInfo)
                    .then(returnToken);
            })
            .catch(invalidate);


        function postToken() {
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
            });
        }

        function getandCacheTokenInfo(res, body) {
            return getTokenInfo(body)
                .spread(cacheToken);
        }

        function getTokenInfo(tokenBody) {
            return $http.get(infoURL+'?access_token='+tokenBody.access_token, {json: true})
                .spread(function(res, infoBody) {
                    var user = {sub: infoBody.agcoUUID,
                                token: infoBody};
                    infoBody.sub = infoBody.agcoUUID;
                    return [hashedHeader, user, tokenBody.expires_in];
                });
        }

        function cacheToken(hashedHeader, tokenInfo, expiry) {
            redis.multi();
            redis.set(hashedHeader, JSON.stringify(tokenInfo));
            redis.expire(hashedHeader, expiry);
            return redis.exec().then(function(){return tokenInfo;});
        }

        function returnToken(tokenInfo) {
            return done(null, tokenInfo);
        }

        function invalidate() {
            return done(null, false);
        }
    });

}

function createOauth2Strategy(options) {
    var redis = Redis.createClient(options.redis),
        infoURL = options.openAMInfoURL;

    function fetchAndCacheUser(token, hashedToken) {
        return $http.get(infoURL + '?access_token=' + token,
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
                redis.multi();
                redis.set(hashedToken, JSON.stringify(user));
                redis.expire(hashedToken, body.expires_in);
                return redis.exec().then(function () { return user });
            });
    }

    return new OAuth2Strategy(function verify(token, done) {
        var hashedToken = oauth2Key(MD5(token));

        return getRedis(redis, hashedToken)
            .then(function checkCache(cachedUser) {
                if (!cachedUser) return fetchAndCacheUser(token, hashedToken);

                return JSON.parse(cachedUser);
            })
            .then(function returnUser(authedUser) {
                return done(null, authedUser);
            })
            .catch(function invalidateAllErrors(err) {
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
