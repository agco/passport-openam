var BasicStrategy = require('passport-http').BasicStrategy,
    OAuth2Strategy = require('passport-http-bearer').Strategy,
    $http = require('http-as-promised'),
    MD5 = require('MD5'),
    promise = require('bluebird'),
    Redis = require('then-redis');

function createBasicStrategy(options) {

    return new BasicStrategy(function(username, password, done) {
        var redis =  Redis.createClient({database: options.redisDBIndex});

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
                error: false,
                rejectUnauthorized: false
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
        var redis = Redis.createClient({database: options.redisDBIndex});

        var hashedToken = MD5(token),
            infoURL = options.openAMInfoURL;

        return getRedis(redis, hashedToken)
            .then(getTokenInfo)
            .spread(storeUser)
            .then(validate)
            .catch(invalidate);

        function getTokenInfo(value) {
            if (value) return done(null, JSON.parse(value));
            return $http.get(infoURL+'?access_token='+token,
                {json: true,
                 error: false});
        }

        function storeUser(res, body) {
            if (body.error || res.statusCode === 404) return done(body, null);
            redis.multi();
            redis.select(options.redisDBIndex);
            redis.set(hashedToken, JSON.stringify(body));
            redis.expire(hashedToken, body.expires_in);
            return redis.exec().then(function() { return body; })
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
