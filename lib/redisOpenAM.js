var BasicStrategy = require('passport-http').BasicStrategy,
    OAuth2Strategy = require('passport-http-bearer').Strategy,
    $http = require('http-as-promised'),
    _ = require('lodash'),
    MD5 = require('MD5'),
    promise = require('bluebird'),
    Redis = require('then-redis');

function createBasicStrategy(options) {
    var redis =  Redis.createClient(options.redis);

    return new BasicStrategy(function(username, password, done) {
        var header = username + ':' + password,
            hashedHeader = MD5(header),
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

};

function createOauth2Strategy(options) {
    var redis = Redis.createClient(options.redis);

    return new OAuth2Strategy(function(token, done) {
        var hashedToken = MD5(token),
            infoURL = options.openAMInfoURL;

        return getRedis(redis, hashedToken)
            .then(function(value) {
                if (value) {
                    return done(null, JSON.parse(value))
                } else {
                    return getTokenInfo()
                        .spread(checkResponse)
                        .then(validateReturn);
                }
            })
            .catch(invalidate);

        function getTokenInfo() {

            return $http.get(infoURL+'?access_token='+token,
                {   json: true,
                    error: false
                });
        }

        function checkResponse(res, body) {
            return (body.error || res.statusCode === 404) ? null : body;
        }

        function validateReturn(tokenInfo) {
            if (!tokenInfo) return done(null, false);
            return storeUser(tokenInfo)
                .then(validate);
        }

        function storeUser(tokenInfo) {
            var user = {sub: tokenInfo.agcoUUID};
            user.token = tokenInfo;
            redis.multi();
            redis.select(options.redisDBIndex);
            redis.set(hashedToken, JSON.stringify(user));
            redis.expire(hashedToken, tokenInfo.expires_in);
            return redis.exec().then(function() { return user; })
        }

        function validate(user) {
            return done(null, user);
        }

        function invalidate(err) {
            return done(err, null);
        }
    });
}

function getRedis(redis, key) {
    return redis.get(key);
}

module.exports = {
    basic: createBasicStrategy,
    oauth2: createOauth2Strategy
};
