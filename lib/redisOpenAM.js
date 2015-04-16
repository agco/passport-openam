var BasicStrategy = require('passport-http').BasicStrategy,
    $http = require('http-as-promised'),
    MD5 = require('MD5');

module.exports = function createStrategy(redis, options) {

    return new BasicStrategy(function(username, password, done) {
        var header = username + ':' + password,
            hashedHeader = MD5(header),
            URL = options.openAMBaseURL;
        return redis.get(hashedHeader).then(function(token) {
            if (token) return done(null, token);
            return $http.post(URL, {
                form: {
                    client_id: options.client_id,
                    client_secret: options.client_secret,
                    grant_type: 'password',
                    username: username,
                    password: password
                },
                error: false,
                rejectUnauthorized: false
            }).spread(function (res, body) {
                var parsedBody = JSON.parse(body),
                    token = parsedBody.access_token,
                    expiry = parsedBody.expires_in;

                redis.multi();
                redis.set(hashedHeader, token);
                redis.expire(hashedHeader, expiry);
                return redis.exec().then(function() {
                    return done(null, token);
                });
            }).catch(function(err) {
                return done(null, false);
            });
        });
    });

};
