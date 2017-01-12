# dontusepasswords

`dontusepasswords` is a go library that provides password-based authentication 
in a way that minimizes the inherent insecurity of passwords. If any more 
secure alternative to passwords exists for your application, use that. If you 
must handle passwords, dontusepasswords is a decent choice.

Seriously. Don't use passwords. They're a terrible security mechanism and a 
search for *problems with passwords* will provide all the condemnation you 
could want. Outsource your authentication to a sensible third party service 
using a technology like SAML, OpenID, or OAuth. That failing, use a central 
database like Active Directory, LDAP, etc. Try to use certificates. Just don't 
take responsibility for people's passwords if you can at all avoid it.

`dontusepasswords` supports pluggable hashing schemes which can be changed 
on-the-fly. When the system-level hashing scheme is changed, individual hashes 
are updated to use the new scheme as the users login. Included schemes are 
bcrypt and scrypt, each with one default profile.
