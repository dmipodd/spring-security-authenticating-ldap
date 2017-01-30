An example of how to implement spring security LDAP authentication with custom authentication provider.
In this example we need a custom authentication provider because the "login" from GUI needs to be previously transformed before sending it to LDAP (example: login - matt.dowson, CN - Matt Dowson).
