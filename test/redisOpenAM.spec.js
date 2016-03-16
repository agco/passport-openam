/**
 * Unit tests for redisOpenAM module.
 */

// dependencies
var should = require('chai').should(),
    Oauth2Strategy = require('passport-http-bearer').Strategy,
    BasicStrategy = require('passport-http').BasicStrategy,
    Nock= require('nock'),
    Redis = require('then-redis');


// module under test
var RedisOpenAM = require('../lib/redisOpenAM');


// constants
var openAMBaseURL = 'https://example.com';
var openAMTokenPath = '/access_token'
var openAMInfoPath = '/tokeninfo';
var openAMUserPath = '/userinfo';
var openAMMock = Nock(openAMBaseURL);
var mockToken = 'db6e6138-3f53-4065-9610-25022a175516';

// tests
describe('Module redisOpenAM', function () {
    var redisDb;

    before(function configRedisDb() {
        redisDb = Redis.createClient();
    });

    beforeEach(function setupMockOptions() {
        redisDb.flushall();
    });

    it('should have property basicKey and be a function', function () {
        RedisOpenAM.should.have.property('basicKey').and.be.a.Function;
    });

    it('should have property oauth2Key and be a function', function () {
        RedisOpenAM.should.have.property('oauth2Key').and.be.a.Function;
    });

    it('should have property basic and be a function', function () {
        RedisOpenAM.should.have.property('basic').and.be.a.Function;
    });

    it('should have property oauth2 and be a function', function () {
        RedisOpenAM.should.have.property('oauth2').and.be.a.Function;
    });

    describe('the createBasicStrategy function', function () {
        var basicStrategy;

        before(function referenceBasicStrategy() {
            basicStrategy = RedisOpenAM.basic({
                openAMBaseURL: openAMBaseURL + openAMTokenPath,
                openAMInfoURL: openAMBaseURL + openAMInfoPath,
                scope: [ 'sub', 'username', 'email'],
                client_id: 'client_id',
                client_secret: 'client_secret',
                redis: {},
            });
        });

        it('should return an instance of BasicStrategy', function () {
            basicStrategy.should.be.an.Object;
            basicStrategy.should.be.an.instanceof(BasicStrategy);
        });

        describe('The verify function used by createBasicStrategy', function () {
            var verify;

            before(function getRefToVerify() {
                verify = basicStrategy._verify;
            });

            it('should be a function', function () {
               verify.should.be.a.Function;
            });

            it('When OpenAM returns any invalid response, ' +
                'should not cache errors in redis', function () {
                openAMMock
                    .post(openAMTokenPath)
                    .reply(200, { access_token: mockToken })
                    .get(openAMInfoPath + '?access_token=' + mockToken)
                    .reply(200, '<div>some html probably with an error message but a statusCode 200 got returned</div>');

                return verify('foo', 'bar', function callback(err, user, info) {
                    return {
                        err: err,
                        user: user,
                        info: info
                    };
                })
                    .then(function validateUserIsFalse(result) {
                        result.user.should.equal(false);
                        return redisDb.keys('*');
                    })
                    .then(function validateNothingCachedInRedis(redisKeyList) {
                        redisKeyList.length.should.equal(0);
                    });
            });
        });
    });

    describe('The createOauth2Strategy function', function () {
        var oauth2Strategy;

        before(function getRefToOauth2Strategy() {
            oauth2Strategy = RedisOpenAM.oauth2({
                redis: {},
                openAMInfoURL: openAMBaseURL + openAMInfoPath,
                openAMUserURL: openAMBaseURL + openAMUserPath
            });
        });

        it('should return an instance of Oauth2Strategy', function () {
            oauth2Strategy.should.be.an.Object;
            oauth2Strategy.should.be.an.instanceof(Oauth2Strategy);
        });

        describe('The verify function used by createOauth2Strategy', function () {
            var verify;

            before(function getRefToVerify() {
                verify = oauth2Strategy._verify;
            });

            it('should be a function', function () {
                verify.should.be.a.Function;
            });

            /**
             * Under high loads, our OpenAM provider is returning a 200 message with some html detailing a 503 error. Our code is not treating this as an
             * error, and as such is caching the html as a user's credentials in Redis, thus giving semi-permanent 401 errors. This test checks that any
             * invalid response from our OpenAM provider is treated as an error and not cached in Redis.
             */
            it('When OpenAM returns any invalid response, ' +
                'should not cache errors in redis', function () {
                openAMMock
                    .get(openAMInfoPath + '?access_token=' + mockToken)
                    .reply(200, '<div>some html probably with an error message but a statusCode 200 got returned</div>');

                return verify(mockToken, function callback(err, user, info) {
                    return {
                        err: err,
                        user: user,
                        info: info
                    };
                })
                    .then(function validateUserIsFalse(result) {
                        result.user.should.equal(false);
                        return redisDb.keys('*');
                    })
                    .then(function validateNothingCachedInRedis(redisKeyList) {
                        redisKeyList.length.should.equal(0);
                    })
            });
        });
    });
});
