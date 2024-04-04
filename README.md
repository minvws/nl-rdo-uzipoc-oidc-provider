# System summary
This repository is meant to act as mock OpenID Connect provider to be used along side [MAX](https://github.com/minvws/nl-rdo-max) 
and [Login Controller](https://github.com/minvws/nl-uzi-login-controller). Designated to be one of the login methods provided by MAX
where 3rd party OIDC Providers can authentication users of client application and retrieve user info from [UZI-register](https://github.com/minvws/nl-uzipoc-register-api).

Please note that this repository is part of a Proof of Concept (PoC), and is not intended to be used in production.

# setup
```bash
make setup
```
# run
```bash
make run
```

### Docker containers
Docker containers and their configurations are meant to be used for development purposes only. And not meant to be used in a production setup.

