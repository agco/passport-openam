# Passport strategy for OpenAM endpoints.

### OAUTH2

This strategy uses OAUTH2 Password Grant to authenticate a user, and queries
the token_info endpoint for user data

### Caching

#### Redis

A redis instance is required to cache users authentication
