nagios
======

Nagios plugins

This nagios plugin checks the password expiration using the command chage. 
The user running this plugin (nagios) must be allowed to run chage under root user 
This implies to add an authorization via sudoer config file. 
As an example, this is the file i added under /etc/sudoers.d directory : 
#------------------- 
User_Alias NAGIOS = nagios 
NAGIOS ALL = NOPASSWD: /usr/bin/chage -l * 
Defaults:NAGIOS !requiretty 
#------------------- 

The output is the following : 
- PASSWD_EXPIRATION OK - ALL VALUES ARE OK!, Excluded account(s): [none] 
- PASSWD_EXPIRATION CRITICAL - Exp < 5j:[root], Excluded account(s): [none] 
- PASSWD_EXPIRATION WARNING - Exp < 6j:[accnt01, accnt02], Excluded account(s): [none] 




help output : 
check_passwd_expiration 1.1 [http://fr.linkedin.com/in/eliocanaleparola/] 

GPL 

Verify password expiration for all accounts defined within /etc/passwd 

Usage: check_passwd_expiration 

-?, --usage 
Print usage information 
-h, --help 
Print detailed help screen 
-V, --version 
Print version information 
--extra-opts=[section][@file] 
Read options from an ini file. See http://nagiosplugins.org/extra-opts 
for usage and examples. 
-w, --warning=STRING 
warning value in days. When a password will expire in days, a warning message is sent 
-c, --critical=STRING 
critical value in days. When a password will expire in days, a critical message is sent 
-x, --exclusion=STRING 
Excluded account list, Format: [account01:account02:account03:...] 
-T, --trace=STRING 
Activate trace mode if value different from 0 
-t, --timeout=INTEGER 
Seconds before plugin times out (default: 15) 
-v, --verbose 
Show details for command-line debugging (can repeat up to 3 times) 
Elio Canale-Parola 

[root@ketik libexec]# 
