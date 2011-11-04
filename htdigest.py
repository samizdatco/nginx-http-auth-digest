#!/usr/bin/env python
# encoding: utf-8
"""
htdigest.py

A barebones stand-in for the apache htdigest tool. It lacks the -c switch of the
original and doesn't handle comments or blank lines. Caveat sysadmin...

Created by Christian Swinehart on 2011-10-30.
Copyright (c) 2011 Samizdat Drafting Co. All rights reserved.
"""

from __future__ import with_statement
import sys
import os
from hashlib import md5
from getpass import getpass

class Passwd(object):
  def __init__(self, pth):
    super(Passwd, self).__init__()
    self.pth = os.path.abspath(pth)
    self.creds = []    
    if not os.path.exists(self.pth):
      while True:
        resp = raw_input('%s does not exist. Create it? (y/n) '%self.pth).lower()
        if resp == 'y': break
        if resp == 'n': sys.exit(1)
    else:
      with file(self.pth) as f:
        for line in f.readlines():
          self.creds.append(line.strip().split(":"))
  
  def update(self, username, realm):
    user_matches = [c for c in self.creds if c[0]==username and c[1]==realm]
    if user_matches:
      password = getpass('Change password for "%s" to: '%username)
    else:
      password = getpass('Password for new user "%s": '%username)
    if password != getpass('Please repeat the password: '):
      print "Passwords didn't match. %s unchanged."%self.pth
      sys.exit(1)
  
    pw_hash = md5(':'.join([username,realm,password])).hexdigest()
    if user_matches:
      user_matches[0][2] = pw_hash
    else:
      self.creds.append([username, realm, pw_hash])
  
    new_passwd = "\n".join(":".join(cred) for cred in self.creds)
    with file(self.pth,'w') as f:
      f.write(new_passwd)
    
if __name__ == '__main__':
  if len(sys.argv) != 4:
    print "usage: htdigest.py passwdfile username 'realm name'"
    sys.exit(1)
  fn,user,realm = sys.argv[1:4]

  passwd = Passwd(fn)
  passwd.update(user,realm)
  