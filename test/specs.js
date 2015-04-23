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

        };

    passport.use(redisOpenAM.basic(db, basicOptions));
    passport.use(redisOpenAM.oauth2(db, oauth2Options));
    app.use(passport.initialize());
    app.get('/foo', passport.authenticate('basic', {session: false}), sendResponse);

    function sendResponse(req, res, next) {
        requestUser = req.user;
        res.send(200);
    }

    var server = app.listen(port, function() {
        var host = server.address().address;
        var port = server.address().port;
        console.log('Test server listening at http://%s:%s', host, port);
    });


});

describe('Basic Auth for routes', function() {

    it('returns 401 for requests without auth headers', function() {

        return $http.get(url + '/foo', {error: false})
            .spread(function(res) {
                expect(res.statusCode).to.equal(401);
            });

    });
});

describe('Basic Authorization', function() {
//
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
//
    describe('openAM check', function() {

        var mockToken = "f6dcf133-f00b-4943-a8d4-ee939fc1bf29";

        before(function() {
            var openAMMock = nock(openAMBaseURL)
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

        after(function() {
            nock.restore();
            return db.flushdb();
        });
    });

});

describe('OAUTH2', function() {

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

});
