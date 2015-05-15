var BasicStrategy = require('passport-http').BasicStrategy,
    OAuth2Strategy = require('passport-http-bearer').Strategy,
    $http = require('http-as-promised'),
    _ = require('lodash'),
    MD5 = require('MD5'),
    promise = require('bluebird'),
    Redis = require('then-redis');

function createBasicStrategy(options) {

    return new BasicStrategy(function(username, password, done) {
        var redis =  Redis.createClient(options.redis);

        var header = username + ':' + password,
            hashedHeader = MD5(header),
            URL = options.openAMBaseURL,
            infoURL = options.openAMInfoURL,
            scopes = options.scope.join('%20'),
            foundToken;

        return getRedis(redis, hashedHeader)
            .then(postToken)
            .spread(cacheAndGetTokenInfo)
            .spread(returnToken)
            .catch(invalidate);

        function postToken(token) {
            if (token) return done(null, token);
            return $http.post(URL, {
                form: {
                    client_id: options.client_id,
                    client_secret: options.client_secret,
                    grant_type: 'password',
                    username: username,
                    password: password,
                    scope: scopes
                },
                error: false
            });
        }

        function cacheAndGetTokenInfo(res, body) {
            var parsedBody = JSON.parse(body);

            foundToken = parsedBody.access_token;

            return promise.all([
                cacheToken(parsedBody),
                getTokenInfo()
            ]);
        }

        function cacheToken(parsedBody) {
            var expiry = parsedBody.expires_in;

            redis.multi();
            redis.set(hashedHeader, foundToken);
            redis.expire(hashedHeader, expiry);
            return redis.exec();
        }

        function getTokenInfo() {
            return $http.get(infoURL+'?access_token='+foundToken, {json: true});
        }

        function returnToken(redisArgs, tokenInfo) {
            return done(null, tokenInfo[1]);
        }

        function invalidate(err) {
            return done(null, false);
        }
    });

};

function createOauth2Strategy(options) {
    return new OAuth2Strategy(function(token, done) {
        var redis = Redis.createClient(options.redis);

        var hashedToken = MD5(token),
            infoURL = options.openAMInfoURL,
            userURL = options.openAMUserURL;

        return getRedis(redis, hashedToken)
            .then(getInfo);

        function getInfo(value) {
            if (value) return done(null, JSON.parse(value));
            return promise.all([getTokenInfo(), getUserInfo()])
                .spread(validateReturns);
        }

        function getTokenInfo() {
            return $http.get(infoURL+'?access_token='+token,
                {   json: true,
                    error: false,
                })
                .spread(checkResponse);
        }

        function getUserInfo() {
            return $http.post(userURL, {
                headers: {
                    Authorization: 'Bearer ' + token
                },
                json: true,
            }).spread(checkResponse);
        }

        function checkResponse(res, body) {
            return (body.error || res.statusCode === 404) ? null : body;
        }

        function validateReturns(token, user) {
            if (!(token && user)) return done(null, false);
            return storeUser(token, user)
                .then(validate)
                .catch(invalidate);
        }

        function storeUser(token, user) {
            user.token = token;
            redis.multi();
            redis.select(options.redisDBIndex);
            redis.set(hashedToken, JSON.stringify(user));
            redis.expire(hashedToken, token.expires_in);
            return redis.exec().then(function() { return user; })
        }

        function validate(user) {
            done(null, user);
        }

        function invalidate(err) {
            done(err, null);
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
