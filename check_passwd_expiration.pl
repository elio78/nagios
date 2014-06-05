#!/usr/bin/perl
#--------------------------------------------------------------------------------------#
# This nagios plugin checks the password expiration using the command chage.           #
# The user running this plugin (nagios) must be allowed to run chage under root user   #
# This implies to add an authorization via sudoer config file.                         #
# As an example, this is the file i added under /etc/sudoers.d directory :             #
#-------------------                                                                   #
#   User_Alias NAGIOS = nagios                                                         #
#   NAGIOS ALL = NOPASSWD: /usr/bin/chage -l *                                         #
#   Defaults:NAGIOS !requiretty                                                        #
#-------------------                                                                   #
# The output is the following :                                                        #
# PASSWD_EXPIRATION OK - ALL VALUES ARE OK!, Excluded account(s): [none]               #
# PASSWD_EXPIRATION CRITICAL - Exp < 5j:[root], Excluded account(s): [none]            #
# PASSWD_EXPIRATION WARNING - Exp < 6j:[accnt01, accnt02], Excluded account(s): [none] #
#--------------------------------------------------------------------------------------#

use Nagios::Plugin;
use File::Basename;
use Nagios::Plugin::Performance;
use Time::Local;
use POSIX;

#--------------------------------PLUGIN SPECIFIC VALUES--------------------------------#
my $VERSION=1.1;
my $blurb="Verify password expiration for all accounts defined within /etc/passwd";
my $extra="Elio Canale-Parola";
my $url="http://fr.linkedin.com/in/eliocanaleparola/";
my $license="GPL";
my $progname=basename($0);

#--------------------------------PLUGIN RETURN CODES-----------------------------------#
$STATE_OK=0;
$STATE_WARNING=1;
$STATE_CRITICAL=2;
$STATE_UNKNOWN=3;

#--------------------------------PRGOGRAM VARIABLES------------------------------------#
my $trace=0;
my $returnCode=0;
my $message="";
my $complement = ", Excluded account(s): ";
my $errorMessage="";
my $msgCritical="";
my $msgWarning="";
my $exclusionList="[none]";
my $timestamp = time();

#This hash tab is used for the date to timestamp conversion
my $listMonth = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec";
my %tabMois = {};
$tabMois{'Jan'} = 0;
$tabMois{'Feb'} = 1;
$tabMois{'Mar'} = 2;
$tabMois{'Apr'} = 3;
$tabMois{'May'} = 4;
$tabMois{'Jun'} = 5;
$tabMois{'Jul'} = 6;
$tabMois{'Aug'} = 7;
$tabMois{'Sep'} = 8;
$tabMois{'Oct'} = 9;
$tabMois{'Nov'} = 10;
$tabMois{'Dec'} = 11;
 
my %tabExpiration = {};
my %tabExpired = {};
my %tabExpirationCritical = {};
my %tabExpirationWarning = {};

#--------------------------------VARIABLES DEFAULT VALUES------------------------------#
my $warningDefault="7";
my $criticalDefault="4";

my $warning = $warningDefault;
my $critical = $criticalDefault;
my $exclusion = "[none]";

my $np = Nagios::Plugin->new(
    usage => "Usage: %s ",
    version => $VERSION,
    blurb   => $blurb,
    extra   => $extra,
    url     => $url,
    license => $license,
    plugin  => basename $0,
    timeout => 3,
);


#--------------------------------------------------------------------------------------#
# defineCallParameters : Define plugin call parameters                                 #
#--------------------------------------------------------------------------------------#
# Call parameters : none                                                               #
# Side effects    : uptade $np global variable, adding plugin call parameters          #
# Return code     : $STATE_OK                                                          #
#--------------------------------------------------------------------------------------#
sub defineCallParameters() {
    my $fct="defineCallParameters";

    # Parameter : warning threshold
    $np->add_arg(
        spec => 'warning|w=s',
        help => "warning value in days. When a password will expire in <w or less> days, a warning message is sent",
        required => 0
    );

    # Parameter : critical threshold
    $np->add_arg(
        spec => 'critical|c=s',
        help => "critical value in days. When a password will expire in <ci or less> days, a critical message is sent",
        required => 0
    );

    # Parameter : list of excluded accounts
    $np->add_arg(
        spec => 'exclusion|x=s',
        help => "Excluded account list, Format: [account01:account02:account03:...]",
        required => 0
    );
    
    # Parameter : trace mode    
    $np->add_arg(
        spec => 'trace|T=s',
        help => "Activate trace mode if value different from 0",
        required => 0
    );
    return($STATE_OK);
}
#--------------------------------------------------------------------------------------#
#                                 END defineCallParameters                             #
#--------------------------------------------------------------------------------------#



#--------------------------------------------------------------------------------------#
# processCallParameters : Parse and process plugin arguments                           #
#--------------------------------------------------------------------------------------#
# Call parameters : none                                                               #
# Side effects    : uptade following global variables, if no input argument            #
#                   is given, default values are used                                  #
#                     trace    : default value is 0 (no trace)                         # 
#                     warning  : warning threshold (days), default : $warningDefault   # 
#                     critical : critical threshold (days), default : $criticalDefault #
#                     exclusionList : default value is null                            #
#                     errorMessage : contains error details in case of errors          #
# Return code     : $STATE_OK if all arguments are valid, otherwhise                   #
#                   $STATE_UNKNOWN, in this case $errorMessage contains a message      #
#--------------------------------------------------------------------------------------#
sub processCallParameters() {
    my $fct="processCallParameters";
    $returnCode = $STATE_OK;
    $np->getopts;
    if ($np->opts->trace) {
        $trace = $np->opts->trace;
    }
    ($trace)? print("DEBUG----:$fct:BEGIN\n"):();
	
    if ($np->opts->warning) {
        $warning = $np->opts->warning;
	if ($warning =~ m/[\d]+/) {
	    ($trace)? print("DEBUG----:$fct:warning threshold= $warning\n"):();
        } else {
            $errorMessage = "Parameter error : Warning parameter [".$warning."] must be an integer";
            $returnCode = $STATE_UNKNOWN;
        }	
    }
    if ($np->opts->critical) {
        $critical = $np->opts->critical;
	if ($critical =~ m/[\d]+/ ) {
	    ($trace)? print("DEBUG----:$fct:critical threshold= $critical\n"):();
        } else {
            $errorMessage = "Parameter error : Critical parameter [".$critical."] must be an integer";
            $returnCode = $STATE_UNKNOWN;
        }	
    }
    if (($np->opts->exclusion =~ y===c)>0) {
        $exclusionList = $np->opts->exclusion;
    }
    $complement = $complement.$exclusionList;
    return($returnCode);
}
#--------------------------------------------------------------------------------------#
#                                 END processCallParameters                            #
#--------------------------------------------------------------------------------------#


#--------------------------------------------------------------------------------------#
# dumpHashTab : this procedure is for debug purpose, it prints the hash table used to  #
#               record the couple(account,expiration)                                  #
#--------------------------------------------------------------------------------------#
# Call parameters : none, this procedure operates on %tabExpiration global variable    #
# Side effects    : display hash table %tabExpiration content                          #
# Return code     : NONE                                                               #
#--------------------------------------------------------------------------------------#
sub dumpHashTab {
    my $tab = shift;
    my @sortedList = sort (keys %{$tab});
    print("Sorted list : @sortedList\n");
    print("----------------------DUMP HASH TABLE BEGIN------------------------\n");
    foreach $a (@sortedList) {
        my $l = ($a =~ y===c);
        if ($l > 0) {
            print("    *ACCOUNT    :$l: $tab->{$a}{'account'}\n");
            print("    *EXPIRATION :$l: $tab->{$a}{'expiration'}\n");
        }
    }
    print("----------------------DUMP HASH TABLE END--------------------------\n");
}
#--------------------------------------------------------------------------------------#
#                                 END dumpHashTab                                      #
#--------------------------------------------------------------------------------------#

#--------------------------------------------------------------------------------------#
# buildMessage: this function builds a character string from a hash table              #
#               the hash table contains a list of accounts and an expiration delay     #
#               the resultant string is composed by a list of all accounts separated   #
#               by a comma.                                                            #
#--------------------------------------------------------------------------------------#
# Call parameters :                                                                    #
#                 hash : refrence to hash table to be processed                        #
#                 header : header string                                               #
#                 trailer: trailer string                                              #
# Side effects    : build a string composed like the following :                       #
#                   header accnt01, accnt02, accnt03 trailer                           #
# Return code     : Result string                                                      #
#--------------------------------------------------------------------------------------#
sub buildMessage {
    my $hash = shift;
    my $header = shift;
    my $trailer = shift;
    my @sortedList = sort (keys %{$hash});
    my $result = "";
    my $count = keys %{$hash};
    ($trace)? print("count = $count\n"):();
    if ($count > 1) {
        $result = $header;
        my $length = ($result =~ y===c);
        foreach $a (@sortedList) {
            my $l = ($a =~ y===c);
            if ($l > 0) {
                my $account = $hash->{$a}{'account'};
               ($trace)? print("account = $account\n"):();
                my $currentLength = ($result =~ y===c);
                my $accountLength = ($account =~ y===c);
                if ($accountLength > 0) {
                    if ($currentLength == $length) {
                        $result=$result.$account;
                    } else {
                        $result=$result.", ".$hash->{$a}{'account'};
                    }
                }
            }
        }
        $result=$result.$trailer;
    }
    return($result);
}
#--------------------------------------------------------------------------------------#
#                                 END buildMessage                                     #
#--------------------------------------------------------------------------------------#


#--------------------------------------------------------------------------------------#
# sendCommand : send commands in order to collect system values necessary for plugin   # 
#--------------------------------------------------------------------------------------#
# Call parameters : none                                                               #
# Prerequisites   : the chage command used is executable only under root account.      #
#                   nagios account must have sudo authorization to execute correctly   #
# Local variables : $cmd : contains the command used to get all /etc/passwd accounts   #
#                   $cmdAge : get expiration value for a specific account              #
# Side effects    : uptade the hash tab global variable with all accounts on which     #
#                   expiration date has been activated                                 #
#                   exluded account (contained within $exclusionList are not prosessed #
# Return code     : number of account with expiration date processed                   #
#--------------------------------------------------------------------------------------#
sub sendCommand {
    my $fct = "sendCommand"; 
    #----------------------------------------------------------------------------------#
    #get all account defined by /etc/passwd file
    #----------------------------------------------------------------------------------#
    $cmd="getent passwd | cut -d':' -f 1";
    ($trace)? print("DEBUG----:$fct:BEGIN\n"):();

    #----------------------------------------------------------------------------------#
    #Send the command $cmd and process each account, verifying expiration data
    #----------------------------------------------------------------------------------#
    foreach $account (`$cmd`) {
        chomp($account);
        if ( ( $account =~ y===c) > 0) {
        #------------------------------------------------------------------------------#
        # chage must run under root account
        #------------------------------------------------------------------------------#
        my $cmdAge = "sudo /usr/bin/chage -l ".$account."| grep Password | grep expires";
        $expiration = `$cmdAge`;
        chomp($expiration);
        if ($expiration =~ m/Password[\s]+expires[\s]+:(.*)/) {
            if ($1 =~ m/.*never.*/) {
                ($trace)? print("Password for account $account never expires\n"):();
            } else {
                ($trace)? print("ligne inseree : $account : $1\n"):();
                my $s = dateToTimestamp($1);
                my $difference = ($s - $timestamp)/(3600*24);
                $tabExpiration{$account}{'account'}=$account;
                $tabExpiration{$account}{'expiration'}=floor($difference);
                ($trace)? print("Retour = $tabExpiration{$account}{'expiration'}\n"):();
            }
        }
	($trace)? print("DEBUG----:$fct:$account:$expiration\n"):();
	($trace)? print("DEBUG----:$fct:END\n"):();
    }
    }
    my $numAccount = keys %tabExpiration;
    return($numAccount);
}#sendCommand
#--------------------------------------------------------------------------------------#
#                                 END sendCommand                                      #
#--------------------------------------------------------------------------------------#

#--------------------------------------------------------------------------------------#
# dateToTimestamp : convert date returned by chage command in timestamp unix           #
#--------------------------------------------------------------------------------------#
# Call parameters : date to be converted with format : Jun 03, 2014                    #
# Side effects    : build a unix timestamp from the given date                         #
# Return code     : timestamp if conversion is done, -1 if error                       #
#--------------------------------------------------------------------------------------#
sub dateToTimestamp { 
  my($s) = @_;
  my $year = 0;
  my $month = 0;
  my $day = 0;
  my $hour = 0;
  my $minutes = 0;
  my $seconds = 0;

  ($trace)? print("Input : $s\n"):();
  if ($s =~ m/[\s]+($listMonth)[\s]+([\d]+)[\s]*\,[\s]*([\d]+)(.*)/ ) {
      $month = $tabMois{$1};
      $day = $2;
      $year = $3;
      ($trace)? print("Mois = $month, Jour = $day, Annee = $year\n"):();
      $year = ($year<100 ? ($year<70 ? 2000+$year : 1900+$year) : $year);
      return timelocal($seconds,$minutes,$hour,$day,$month,$year);  
  }
  return -1;
}
#--------------------------------------------------------------------------------------#
#                                 END dateToTimestamp                                  #
#--------------------------------------------------------------------------------------#


#--------------------------------------------------------------------------------------#
# computeValues : analyse hash table %tabExpiration and build three hash tables :      #
#                 tabExpired : all expired accounts
#                 tabExpirationCritical : accounts with expiration delay is less than  #
#                                         critical threshold                           #
#                 tabExpirationWarning  : accounts with expiration delay is less than  #
#                                         warning threshold                            #
#--------------------------------------------------------------------------------------#
# Call parameters : none (uses %tabExpiration global variable)                         #
# Side effects    : builds 3 tables as mentionned above                                #
# Return code     : $STATE_OK if no warning or critical expiration delay is found      #
#                   $STATE_CRITICAL if at least one critical expiration delay is found #
#                   $STATE_WARNING if at least one warning expiration delay is found   #
#--------------------------------------------------------------------------------------#
sub computeValues {
    my $fct = "computeValues";
    my $returnCode = $STATE_OK;
    ($trace)? print("DEBUG----:$fct:BEGIN\n"):();
    my @listeTriee = sort (keys (%tabExpiration));
    foreach $a (@listeTriee) {
        my $account = $tabExpiration{$a}{'account'};
        my $expiration = $tabExpiration{$a}{'expiration'};
        if (($account =~ y===c) <= 0) {
            next;
        }
        if ($exclusionList =~m/$account/) {
            ($trace)? print("Account : $account is excluded from control\n"):();
        } elsif ($expiration < 0) {
            $tabExpired{$account}{'account'}=$account;
            $tabExpired{$account}{'expiration'}=$expiration;
            $msgCritical = $msgCritical.$account."since ".$expiration."j ";
            $returnCode = $STATE_CRITICAL;
        } elsif ($expiration < $critical) {
            #Traitement alerte critique
            $tabExpirationCritical{$account}{'account'}=$account;
            $tabExpirationCritical{$account}{'expiration'}=$expiration;
            $msgCritical = $msgCritical.$account."within ".$expiration."j ";
            ($trace)? print("CRITIQUE : Le compte $account, expire dans $delai day(s)\n"):();
            $returnCode = $STATE_CRITICAL;
        } elsif ($expiration < $warning) {
            $tabExpirationWarning{$account}{'account'}=$account;
            $tabExpirationWarning{$account}{'expiration'}=$expiration;
            #Traitement alerte warning
            $msgWarning = $msgWarning.$account."within ".$expiration."j ";
            if ( $returnCode != $STATE_CRITICAL) {
                $returnCode = $STATE_WARNING;
            }
            ($trace)? print("WARNING : Account $account, expires within $expiration day(s)\n"):();
        }
    }
    return($returnCode);
} #computeValues
#--------------------------------------------------------------------------------------#
#                                 END computeValues                                    #
#--------------------------------------------------------------------------------------#

#--------------------------------------------------------------------------------------#
#                                       MAIN                                           #
#--------------------------------------------------------------------------------------#
# Call parameters : none                                                               #
# Side effects    : Check if account located in /etc/passwd file are expired or will   #
#                   expire soon.                                                       #
# Return code     : Standard nagios return code according to accounts situation        #
#--------------------------------------------------------------------------------------#

#--------------------------------------------------------------------------------------#
# Define nagios plugin call parameters                                                 #
#--------------------------------------------------------------------------------------#
my $e1 = defineCallParameters();
if ($e1 != 0) {
    $np->nagios_exit( UNKNOWN, $errorMessage );
}
#--------------------------------------------------------------------------------------#
# Process plugin call parameters                                                       #
#--------------------------------------------------------------------------------------#
my $e2 = processCallParameters();
if ($e2 != 0) {
    $np->nagios_exit( UNKNOWN, $errorMessage );
}
#--------------------------------------------------------------------------------------#
# Send system commands in order to build hash table %tabExpiration                     #
#--------------------------------------------------------------------------------------#
my $e3 = sendCommand();

#--------------------------------------------------------------------------------------#
# Check expiration values and build output messages                                    #
#--------------------------------------------------------------------------------------#
$returnCode = computeValues();
$listCritical = buildMessage(\%tabExpirationCritical,"Exp < ".$critical."j:[","]");
$listWarning = buildMessage(\%tabExpirationWarning,"Exp < ".$warning."j:[","]");



#--------------------------------------------------------------------------------------#
# Format message according to nagios plugin standard                                   #
#--------------------------------------------------------------------------------------#
if ( $returnCode == $STATE_CRITICAL) {
    $message = $message.$listCritical.$complement;
    $np->nagios_exit( CRITICAL, $message );
} elsif ($returnCode == $STATE_WARNING) {
    $message = $message.$listWarning.$complement;
    $np->nagios_exit( WARNING, $message );
} else {
    $message = "ALL VALUES ARE OK!".$complement;
    $np->nagios_exit( OK, $message );
}                    
