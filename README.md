# spring-boot-jwt-demo
This repository is intended as an example to do authentication using JWT

Before authorized every request, the request has to check whether the token still valid by checking the registered ID in Consul KV Database.

If the token expired, then the registered ID has to be removed from KV database
