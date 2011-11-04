==================================
Nginx Digest Authentication module
==================================

.. contents::

The ``ngx_http_auth_digest`` module supplements Nginx_'s built-in Basic Authentication module by providing support for RFC 2617 Digest Authentication. The module is currently functional but 
untested (and unreviewed) and thus inherently not ready for use in production. 

Please see the bugs.txt file for a listing of the remaining roadblocks, and please consider contributing a patch if you have the time and inclination. Any help fixing the bugs or changing the implementation to a more idiomatically nginx-y one would be greatly appreciated.

Dependencies
============
* Sources for Nginx_ 1.0.8, and its dependencies.


Building
========

1. Unpack the Nginx_ sources::

    $ tar zxvf nginx-1.0.8.tar.gz

2. Unpack the sources for the digest module::

    $ tar xzvf samizdatco-ngx-http-auth-digest-xxxxxxx.tar.gz

3. Change to the directory which contains the Nginx_ sources, run the
   configuration script with the desired options and be sure to put an
   ``--add-module`` flag pointing to the directory which contains the source
   of the digest module::

    $ cd nginx-1.0.8
    $ ./configure --add-module=../samizdatco-ngx-http-auth-digest-xxxxxxx  [other configure options]

4. Build and install the software::

    $ make && sudo make install

5. Configure Nginx_ using the module's configuration directives_.


Example
=======

You can password-protect a directory tree by adding the following lines into
a ``server`` section in your Nginx_ configuration file::

  auth_digest_shm_size 512k;
  auth_digest_user_file /opt/httpd/conf/passwd.digest; # a file created with htdigest

  location /{
    auth_digest 'this is not for you'; # set the realm for this location block
    auth_digest_timeout 60s; # allow users to wait 1 minute between receiving the
                             # challenge and hitting send in the browser dialog box
    auth_digest_expires 10s; # after a successful challenge/response, let the client
                             # continue to use the same nonce for additional requests
                             # for 10 seconds before generating a new challenge
    auth_digest_replays 12;  # also generate a new challenge if the client uses the
                             # same nonce more than 12 times before the expire time limit

    location /pub{
      auth_digest off;       # this sub-tree will be accessible without authentication
    }
  }

Note that the only mandatory directives are ``auth_digest`` and ``auth_user_file``, but do consider whether the default value of auth_digest_shm_size is appropriate for your site.

Directives
==========

auth_digest
~~~~~~~~~~~
:Syntax:  auth_digest [*realm-name* | "off"]
:Default: off
:Context: server, location
:Description:
  Enable or disable digest authentication for a server or location block. The realm name
  should correspond to a realm used in the user file. Any user within that realm will be
  able to access files after authenticating.
  
  To selectively disable authentication within a protected uri hierarchy, set auth_digest 
  to "off" within a more-specific location block (see example).
  
  
auth_digest_user_file
~~~~~~~~~~~~~~~~~~~~~
:Syntax: auth_digest_user_file */path/to/passwd/file*
:Default: *unset*
:Context: server, location
:Description:
  Path to the password file. This file should be of the form created by the apache htdigest
  command (or the included htdigest.py script). Each line of the file is a colon-separated 
  list composed of a username, realm, and md5 hash combining name, realm, and password.  
  
auth_digest_timeout
~~~~~~~~~~~~~~~~~~~
:Syntax: auth_digest_timeout *delay-time*
:Default: 60s
:Context: server, location
:Description:
  When a client first requests a protected page, it is sent a challenge with a 401 status code.
  At this point most browsers will present a dialog box to the user prompting them to log in. 
  The `auth_digest_timeout` directive defines how long challenges will remain valid. If the user
  waits longer than this time before submitting their name and password, the challenge will be 
  considered ‘stale’ and they will be prompted to log in again.
    
auth_digest_expires
~~~~~~~~~~~~~~~~~~~
:Syntax: auth_digest_expires *lifetime-in-seconds*
:Default: 10s
:Context: server, location
:Description:
  Once a digest challenge has been successfully answered by the client, subsequent requests 
  will attempt to re-use the ‘nonce’ value from the original challenge. To complicate mitm
  attacks, it's best to limit the number of times a cached nonce will be accepted. This
  directive sets the duration for this re-use period after the first successful authentication.

auth_digest_replays
~~~~~~~~~~~~~~~~~~~
:Syntax: auth_digest_expires *number-of-uses*
:Default: 20
:Context: server, location
:Description:
  Nonce re-use should also be limited to a fixed number of requests. Note that increasing this
  value will cause a proportional increase in memory usage and the shm_size may have to be
  adjusted to keep up with heavy traffic within the digest-protected location blocks.

auth_digest_shm_size
~~~~~~~~~~~~~~~~~~~~
:Syntax: auth_digest_shm_size *size-in-bytes*
:Default: 512k
:Context: server
:Description:
  The module maintains a pool of memory to save state between authenticated requests. Choosing
  the proper size is a little tricky since it depends upon the values set in the other directives.
  Each stored challenge takes up ``48 + replays/8`` bytes and will live for up to ``auth_digest_timeout + auth_digest_expires`` seconds. Using the default module settings this 
  translates into allowing around 10k non-replay requests every 70 seconds.
  

.. _nginx: http://nginx.net
