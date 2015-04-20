var BasicStrategy = require('passport-http').BasicStrategy,
    $http = require('http-as-promised'),
    MD5 = require('MD5'),
    promise = require('bluebird');

module.exports = function createStrategy(redis, options) {

    return new BasicStrategy(function(username, password, done) {
        var header = username + ':' + password,
            hashedHeader = MD5(header),
            URL = options.openAMBaseURL,
            infoURL = options.openAMInfoURL,
            redisIndex = options.redisDBIndex,
            scopes = options.scope.join('%20'),
            foundToken;

        return getHashedHeader()
            .spread(postToken)
            .spread(cacheAndGetTokenInfo)
            .spread(returnToken)
            .catch(invalidate);

        function getHashedHeader() {
            redis.multi();
            redis.select(redisIndex);
            redis.get(hashedHeader);

            return redis.exec();
        }

        function postToken(selectStatus, token) {
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
