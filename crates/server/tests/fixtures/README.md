`idp-key.pem` is a throwaway RSA key generated for the login tests
(`openssl genpkey -algorithm RSA`); `idp-jwks.json` is its public half as the
JWKS a fake identity provider serves. It is trusted by nothing outside the
tests.
