# sc-authd
Simple SmartCard authentication daemon

Tested and works only for Mastercard International EMV cards (and it is not certain).

## Installation
* Install `libpam-script` package
* Copy sc-auth.py and sc-auth.py to /usr/bin/
  ```
  $ chmod +x sc-auth.py sc-authd.py
  # cp sc-auth.py /usr/bin/sc-auth
  # cp sc-authd.py /usr/bin/sc-auth
  ```
* Install and run systemd service
  ```
  # cp sc-auth.service /etc/systemd/system/
  # systemctl enable sc-auth.service
  # systemctl start sc-auth.service
  ```
* Read and save your PAM (card number)
  ```
  # sc-auth -c /usr/share/libpam-script/pam-script.d/pan.hash
  ```
* Copy PAM auth script
  ```
  $ chmod +x pam_script_auth
  # cp pam_script_auth /usr/share/libpam-script/
  ```
* Configure PAM - open `/etc/pam.d/common-auth` and make it looks like this example
  Main line is `auth    [success=2 default=ignore]	pam_script.so`
  It's highly recommended to read [this](https://www.digitalocean.com/community/tutorials/how-to-use-pam-to-configure-authentication-on-an-ubuntu-12-04-vps) article about PAM configuration.
  ```
  #
  # /etc/pam.d/common-auth - authentication settings common to all services
  #
  # This file is included from other service-specific PAM config files,
  # and should contain a list of the authentication modules that define
  # the central authentication scheme for use on the system
  # (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
  # traditional Unix authentication mechanisms.
  #
  # As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
  # To take advantage of this, it is recommended that you configure any
  # local modules either before or after the default block, and use
  # pam-auth-update to manage selection of other modules.  See
  # pam-auth-update(8) for details.

  # here are the per-package modules (the "Primary" block)
  auth	[success=3 default=ignore]	pam_fprintd.so max_tries=1 timeout=10 # debug
  auth    [success=2 default=ignore]	pam_script.so
  auth	[success=1 default=ignore]	pam_unix.so nullok_secure try_first_pass
  # here's the fallback if no module succeeds
  auth	requisite			pam_deny.so
  # prime the stack with a positive return value if there isn't one already;
  # this avoids us returning an error just because nothing sets a success code
  # since the modules above will each just jump around
  auth	required			pam_permit.so
  # and here are more per-package modules (the "Additional" block)
  # end of pam-auth-update config
  ```
* 
