# Passport strategy for OpenAM endpoints.

### OAUTH2

This strategy uses OAUTH2 Password Grant to authenticate a user, and queries
the token_info endpoint for user data

### Caching

#### Redis

A redis instance is required to cache users authentication

### A word about `node` versions.

The test suite will fail some test if it's run with `node` v0.10.25. This is the
default version from ubuntu's repositories. The test has been tested and passes
with `node` v0.10.38 and v0.12.2.