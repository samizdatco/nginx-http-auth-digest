==================================
Nginx Digest Authentication module
==================================

The ``ngx_http_auth_digest`` module supplements Nginx_'s built-in Basic Authentication `module`_ by providing support for `RFC`_ 2617 `Digest Authentication`_. The module is currently functional but has only been tested and reviewed by its author. And given that this is security code, one set of eyes is almost certainly insufficient to guarantee that it's 100% correct. Until a few bug reports come in and some of the ‘unknown unknowns’ in the code are flushed out, consider this module an ‘alpha’ and treat it with the appropriate amount of skepticism.

A listing of known issues with the module can be found in the ``bugs.txt`` file as well as in the `Issue Tracker`_. Please do consider contributing a patch if you have the time and inclination. Any help fixing the bugs or changing the implementation to a more idiomatically nginx-y one would be greatly appreciated.

Dependencies
============
* Sources for Nginx_ 1.0.x, and its dependencies.


Building
========

1. Unpack the Nginx_ sources::

    $ tar zxvf nginx-1.0.x.tar.gz

2. Unpack the sources for the digest module::

    $ tar xzvf samizdatco-nginx-http-auth-digest-xxxxxxx.tar.gz

3. Change to the directory which contains the Nginx_ sources, run the
   configuration script with the desired options and be sure to put an
   ``--add-module`` flag pointing to the directory which contains the source
   of the digest module::

    $ cd nginx-1.0.x
    $ ./configure --add-module=../samizdatco-nginx-http-auth-digest-xxxxxxx  [other configure options]

4. Build and install the software::

    $ make && sudo make install

5. Configure Nginx_ using the module's configuration directives_.


Example
=======

You can password-protect a directory tree by adding the following lines into
a ``server`` section in your Nginx_ configuration file::

  auth_digest_user_file /opt/httpd/conf/passwd.digest; # a file created with htdigest
  location /private{
    auth_digest 'this is not for you'; # set the realm for this location block
  }


The other directives control the lifespan defaults for the authentication session. The 
following is equivalent to the previous example but demonstrates all the directives::

  auth_digest_user_file /opt/httpd/conf/passwd.digest;
  auth_digest_shm_size 4m;   # the storage space allocated for tracking active sessions

  location /private {
    auth_digest 'this is not for you';
    auth_digest_timeout 60s; # allow users to wait 1 minute between receiving the
                             # challenge and hitting send in the browser dialog box
    auth_digest_expires 10s; # after a successful challenge/response, let the client
                             # continue to use the same nonce for additional requests
                             # for 10 seconds before generating a new challenge
    auth_digest_replays 20;  # also generate a new challenge if the client uses the
                             # same nonce more than 20 times before the expire time limit
  }

Adding digest authentication to a location will affect any uris that match that block. To
disable authentication for specific sub-branches off a uri, set ``auth_digest`` to ``off``::

  location / {
    auth_digest 'this is not for you';
    location /pub {
      auth_digest off; # this sub-tree will be accessible without authentication
    }
  }

Directives
==========

auth_digest
~~~~~~~~~~~
:Syntax:  ``auth_digest`` [*realm-name* | ``off``]
:Default: ``off``
:Context: server, location
:Description:
  Enable or disable digest authentication for a server or location block. The realm name
  should correspond to a realm used in the user file. Any user within that realm will be
  able to access files after authenticating.
  
  To selectively disable authentication within a protected uri hierarchy, set ``auth_digest`` 
  to “``off``” within a more-specific location block (see example).
  
  
auth_digest_user_file
~~~~~~~~~~~~~~~~~~~~~
:Syntax: ``auth_digest_user_file`` */path/to/passwd/file*
:Default: *unset*
:Context: server, location
:Description:
  The password file should be of the form created by the apache ``htdigest`` command (or the 
  included `htdigest.py`_ script). Each line of the file is a colon-separated list composed 
  of a username, realm, and md5 hash combining name, realm, and password. For example:
  ``joi:enfield:ef25e85b34208c246cfd09ab76b01db7``
  
auth_digest_timeout
~~~~~~~~~~~~~~~~~~~
:Syntax: ``auth_digest_timeout`` *delay-time*
:Default: ``60s``
:Context: server, location
:Description:
  When a client first requests a protected page, the server returns a 401 status code along with
  a challenge in the ``www-authenticate`` header.
  
  At this point most browsers will present a dialog box to the user prompting them to log in. This
  directive defines how long challenges will remain valid. If the user waits longer than this time
  before submitting their name and password, the challenge will be considered ‘stale’ and they will
  be prompted to log in again.
  
auth_digest_expires
~~~~~~~~~~~~~~~~~~~
:Syntax: ``auth_digest_expires`` *lifetime-in-seconds*
:Default: ``10s``
:Context: server, location
:Description:
  Once a digest challenge has been successfully answered by the client, subsequent requests 
  will attempt to re-use the ‘nonce’ value from the original challenge. To complicate MitM_
  attacks, it's best to limit the number of times a cached nonce will be accepted. This
  directive sets the duration for this re-use period after the first successful authentication.

auth_digest_replays
~~~~~~~~~~~~~~~~~~~
:Syntax: ``auth_digest_replays`` *number-of-uses*
:Default: ``20``
:Context: server, location
:Description:
  Nonce re-use should also be limited to a fixed number of requests. Note that increasing this
  value will cause a proportional increase in memory usage and the shm_size may have to be
  adjusted to keep up with heavy traffic within the digest-protected location blocks.

auth_digest_shm_size
~~~~~~~~~~~~~~~~~~~~
:Syntax: ``auth_digest_shm_size`` *size-in-bytes*
:Default: ``4096k``
:Context: server
:Description:
  The module maintains a fixed-size cache of active digest sessions to save state between 
  authenticated requests. Once this cache is full, no further authentication will be possible
  until active sessions expire. 
  
  As a result, choosing the proper size is a little tricky since it depends upon the values set in
  the expiration-related directives. Each stored challenge takes up ``48 + ceil(replays/8)`` bytes
  and will live for up to ``auth_digest_timeout + auth_digest_expires`` seconds. When using the
  default module settings this translates into allowing around 82k non-replay requests every 70
  seconds.

.. _nginx: http://nginx.net
.. _module: http://wiki.nginx.org/HttpAuthBasicModule
.. _htdigest.py: https://github.com/samizdatco/nginx-http-auth-digest/blob/master/htdigest.py
.. _RFC: http://www.ietf.org/rfc/rfc2617.txt
.. _Digest Authentication: http://en.wikipedia.org/wiki/Digest_access_authentication
.. _Issue Tracker: https://github.com/samizdatco/nginx-http-auth-digest/issues
.. _MitM: http://en.wikipedia.org/wiki/Man-in-the-middle_attack