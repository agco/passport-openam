/**
 * Unit tests for redisOpenAM module.
 */

// dependencies
var should = require('chai').should();
var Strategy = require('passport-http-bearer');
var nock = require('nock')
var Redis = require('then-redis')


// module under test
var RedisOpenAM = require('../lib/redisOpenAM');


// constants
var openAMBaseURL = 'https://example.com';
var openAMInfoPath = '/tokeninfo';
var openAMUserPath = '/userinfo';
var openAMMock = nock(openAMBaseURL);

// tests
describe('Module redisOpenAM', function () {
    var redisDb;

    before(function configRedisDb() {
        redisDb = Redis.createClient();
    });

    beforeEach(function cleanup() {
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

    describe('The createOauth2Strategy function', function () {
        var oauth2Strategy,
            mockOptions;

        before(function createOptionsMock() {
            mockOptions = {
                redis: {},
                openAMInfoURL: openAMBaseURL + openAMInfoPath,
                openAMUserURL: openAMBaseURL + openAMUserPath
            };
            oauth2Strategy = RedisOpenAM.oauth2(mockOptions);
        });

        it('should return an instance of Strategy', function () {
            oauth2Strategy.should.be.an.Object;
            oauth2Strategy.should.be.an.instanceof(Strategy);
        });

        describe('The verify function used by createOauth2Strategy', function () {
            var verify;

            before(function getRefToVerify() {
                verify = oauth2Strategy._verify;
            })

            it('should be a function', function () {
                verify.should.be.a.Function;
            })

            /**
             * Under high loads, our OpenAM provider is returning a 200 message with some html detailing a 503 error. Our code is not treating this as an
             * error, and as such is caching the html as a user's credentials in Redis, thus giving semi-permanent 401 errors. This test checks that any
             * invalid response from our OpenAM provider is treated as an error and not cached in Redis.
             */
            it('When OpenAM returns any invalid response, ' +
                'should not cache errors in redis', function () {
                var mockToken = 'db6e6138-3f53-4065-9610-25022a175516';

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
