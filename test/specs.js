var expect = require('chai').expect,
    $http = require('http-as-promised'),
    MD5 = require('MD5'),
    nock = require('nock'),
    redis = require('then-redis'),
    db = redis.createClient(),
    express = require('express'),
    passport = require('passport'),
    app = express(),
    redisOpenAM = require('../index.js'),
    port = '5050',
    url = 'http://0.0.0.0:'+port,
    openAMBaseURL = 'https://openam.example.com',
    openAMTokenPath = '/auth/oauth2/access_token',
    openAMInfoPath = '/auth/oauth2/tokeninfo',
    openAMURL = openAMBaseURL + openAMTokenPath,
    mockToken = "f6dcf133-f00b-4943-a8d4-ee939fc1bf29",
    expectedUsername = 'foo',
    openAMMock = nock(openAMBaseURL),
    requestUser;

nock.enableNetConnect();

before(function() {
    var basicOptions = {
            openAMBaseURL: openAMURL,
            openAMInfoURL: openAMBaseURL + openAMInfoPath,
            client_id: 'client_id',
            client_secret: 'client_secret',
            redisDBIndex: 1,
            scope: ["UUID", "username", "email"]
        },
        oauth2Options = {
            openAMInfoURL: openAMBaseURL + openAMInfoPath,
            redisDBIndex: 2
        };

    passport.use(redisOpenAM.basic(basicOptions));
    passport.use(redisOpenAM.oauth2(oauth2Options));
    app.use(passport.initialize());
    app.get('/foo', passport.authenticate('basic', {session: false}), sendResponse);
    app.get('/bar', passport.authenticate('bearer', {session: false}), sendResponse);

    function sendResponse(req, res, next) {
        requestUser = req.user;
        res.sendStatus(200);
    }

    var server = app.listen(port, function() {
        var host = server.address().address;
        var port = server.address().port;
        console.log('Test server listening at http://%s:%s', host, port);
    });

});

describe('Basic Authorization', function() {

    it('returns 401 for requests without auth headers', function() {

        return $http.get(url + '/foo', {error: false})
            .spread(function(res) {
                expect(res.statusCode).to.equal(401);
            });

    });

    describe('Redis caches authentication', function() {
        var user = 'foo',
            pass = 'bar',
            token = 'qux';

        before(function() {
            //create

            var header = user + ':' + pass;
            var hashedHeader = MD5(header);

            db.multi();
            db.select(1);
            db.set(hashedHeader, token);

            return db.exec();
        });

        it('checks for an existing base64 token to auth', function() {
            return $http.get(url + '/foo', {
                error: false,
                auth: {
                    user: user,
                    pass: pass
                }
            })
            .spread(function(res, body) {
                expect(res.statusCode).to.equal(200);
            });
        });

    });

    describe('openAM check', function() {

        before(function() {
            openAMMock
                .post(openAMTokenPath)
                .reply(200, {
                    "expires_in": 599,
                    "token_type": "Bearer",
                    "refresh_token": "f9063e26-3a29-41ec-86de-1d0d68aa85e9",
                    "access_token": mockToken
                })
                .get(openAMInfoPath+'?access_token='+mockToken)
                .reply(200, {
                    "UUID": "h234ljb234jkn23",
                    "scope": [
                        "UUID",
                        "username",
                        "email"
                    ],
                    "username": "demo",
                    "email": "foo@bar.com"
                })
                .post(openAMTokenPath)
                .reply(400);
        });

        after(function() {
            return db.flushdb();
        });

        it('validates a user if their credentials exist in openAM and returns '+
            'their token info', function() {
            var user = 'missing',
                pass = 'missing';

            return $http.get(url + '/foo', {
                error: false,
                auth: {
                    user: user,
                    pass: pass
                },
                json: {
                    deviceId: true
                }
            })
            .spread(function(res, body) {
                expect(res.statusCode).to.equal(200);

                var header = user + ':' + pass,
                hashedHeader = MD5(header);

                expect(requestUser.UUID).to.exist;
                expect(requestUser.username).to.exist;
                expect(requestUser.email).to.exist;

                return db.select(1).then(getHeader).then(checkToken);

                function getHeader() {
                    return db.get(hashedHeader);
                }

                function checkToken(token) {
                    expect(token).to.equal(mockToken);
                }

            });
        });

        it('invalidates a user if openAM returns a 400 code', function() {
            var user = 'invalid',
                pass = 'invalid';

            return $http.get(url + '/foo', {
                error: false,
                auth: {
                    user: user,
                    pass: pass
                },
                json: {
                    deviceId: true
                }
            })
            .spread(function(res, body) {
                expect(res.statusCode).to.equal(401);
            });
        });
    });
});

describe('OAUTH2', function() {

    it('returns 401 for requests without auth headers', function() {

        return $http.get(url + '/bar', {error: false})
            .spread(function(res) {
                expect(res.statusCode).to.equal(401);
            });

    });

    describe('Redis caches authentication', function() {
        var token = 'qux',
            tokenHeader = 'Bearer ' + token,
            expectedName = 'Robot';

        before(function() {
            //create token with info

            var hashedHeader = MD5(token),
                userInfo = {
                    name: expectedName
                };

            db.multi();
            db.select(2);
            db.set(hashedHeader, JSON.stringify(userInfo));

            return db.exec();
        });

        it('checks for an existing oauth2 token to auth', function() {
            return $http.get(url + '/bar', {
                error: false,
                headers: {
                    Authorization: tokenHeader
                }
            })
                .spread(function(res, body) {
                    expect(res.statusCode).to.equal(200);
                    expect(requestUser.name).to.equal(expectedName);
                });
        });

    });

    describe('Tokens not in redis are checked against the provided tokeninfo '+
             'endpoint', function() {
        var mockUser = {
                "UUID": "h234ljb234jkn23",
                "scope": [
                    "UUID",
                    "username",
                    "email"
                ],
                "expires_in": 7000,
                "username": expectedUsername,
                "email": "foo@bar.com"
            },
            error = {
                "error": "Not found",
                "error_description": "Could not read token in CTS"
            },
            badToken = 'foo';

        before(function() {
            openAMMock
                .get(openAMInfoPath+'?access_token='+mockToken)
                .reply(200, mockUser)
                .get(openAMInfoPath+'?access_token='+badToken)
                .reply(404, error);
        });

        after(function() {
            return db.flushdb();
        });

        it('Has the user info on the req body if it is found and stores it in '+
            'redis', function() {
            return $http.get(url + '/bar', {
                error: false,
                headers: {
                    Authorization: 'Bearer ' + mockToken
                }
            })
                .spread(function(res, body) {
                    var hashedToken = MD5(mockToken);

                    expect(res.statusCode).to.equal(200);
                    expect(requestUser.username).to.equal(expectedUsername);

                    db.multi();
                    db.select(2);
                    db.get(hashedToken);
                    return db.exec().spread(function(selection, body) {
                        return expect(JSON.parse(body)).to.deep.equal(mockUser);
                    });
                });
        });

        it('invalidates a user if oauth returns 400', function() {
            return $http.get(url + '/bar', {
                error: false,
                headers: {
                    Authorization: 'Bearer ' + 'foo'
                }
            })
                .spread(function(res, body) {
                    expect(res.statusCode).to.equal(401);
                    var hashedToken = MD5(badToken);

                    db.multi();
                    db.select(2);
                    db.get(hashedToken);
                    return db.exec().spread(function(selection, body) {
                        expect(body).to.equal(null);
                    });
                });
        });
    });
});
