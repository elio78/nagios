#!/usr/bin/perl
#--------------------------------------------------------------------------------------#
# This nagios plugin checks an url given in parameters and search for a specific string#
#--------------------------------------------------------------------------------------#

use Nagios::Plugin;
use File::Basename;
use Nagios::Plugin::Performance;
use Time::Local;
use POSIX;
use Time::HiRes qw( gettimeofday tv_interval);
use Data::Dumper qw(Dumper);
use IO::Socket::SSL;
use Mail::IMAPClient;
use Crypt::CBC;
use MIME::Base64;

#-------------------------NAGIOS PLUGIN SPECIFIC VALUES--------------------------------#
my $VERSION=1.1;
my $blurb="Count unseen or present mails within a specific mailbox";
my $extra="Elio Canale-Parola";
my $url="http://fr.linkedin.com/in/eliocanaleparola/";
my $license="GPL";
my $progname=basename($0);
my $STATE_OK=0;
my $STATE_WARNING=1;
my $STATE_CRITICAL=2;
my $STATE_UNKNOWN=3;
my $STATE_DEPENDENT=4;

#-------------------------------PROGRAM SPECIFIC VALUES--------------------------------#
my $KEY = 'secret_foo'; #Key used to crypt passwords
my $login  = '';
my $passwd = '';                ## mot de passe
my $generatePassword = 0;
my $clear_mdp = "xxxx";
my $ficMdp = "/usr/local/nagios/libexec/mdp.txt"; #File used to store email account encrypted passwords
my %userList = {};

#-------------------------------PROGRAM DEFAULT VALUES---------------------------------#
my $trace=0;
my $returnCode=$STATE_OK;
my $warning_cnx  = 3000;
my $critical_cnx = 5000;
my $warning  = 50;
my $critical = 90;
my $ssl = 1;
my $mailServer = 'myemail.server.com';       ## email server address
my $user = '';
my @folders = ("INBOX"); #Comma separated folders list
my $disposition = 'P';   #Disposition used to count mails P=present, U=unread


#-----------------------NAGIOS PLUGIN STRUCTURE (GLOVAL VARIABLE)----------------------#
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

    # Parameter : list of folders
    $np->add_arg(
        spec => 'folder_list|l=s',
        help => "List of folders to request. Format \"[folder1,folder2,...]\"",
        required => 0
    );

    # Parameter : User used to connect to the mailbox
    $np->add_arg(
        spec => 'user|u=s',
        help => "User account used ",
        required => 1
    );

    # Parameter : Generate an encrypted password from given parameter
    $np->add_arg(
        spec => 'generate|g=s',
        help => "Generate a crypted password from given parameter ",
        required => 0
    );

    # Parameter : warning threshold
    $np->add_arg(
        spec => 'warning|w=s',
        help => "warning threshold in number of unread mails per folder. When unread messages are over this threshold, a warning message is sent",
        required => 0
    );

    # Parameter : critical threshold
    $np->add_arg(
        spec => 'critical|c=s',
        help => "critical threshold in number of unread mails per folder. When unread messages are over this threshold, a critical message is sent",
        required => 0
    );

    # Parameter : trace mode
    $np->add_arg(
        spec => 'trace|t=s',
        help => "Activate trace mode if value different from 0",
        required => 0
    );

    # Parameter : disposition
    $np->add_arg(
        spec => 'disposition|D=s',
        help => "Disposition when counting mails (P=count present mails , U=count unseen mails)",
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
#                     folders  : list of folders to analyze                            #
#                     user     : User used to connect to the mailbox                   #
#                     disposition : Way to count messages in the mailbox               #
#                     warning  : warning threshold in unread messages                  #
#                     critical : critical threshold in unread messages                 #
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

    if ($np->opts->folder_list) {
        my $folder_list = $np->opts->folder_list;
        #Remove [ and ] characters;
        $folder_list =~ s/^\[//;
        $folder_list =~ s/\]$//;
        @folders = split(/,/,$folder_list);
        my $nbFolders = @folders; 
        if ($nbFolders > 0) {
            foreach(@folders) {
               $folderList = sprintf("%s %s",$folderList,$_); 
            }
            ($trace)? print Dumper \@folders:();
        } else {
            $errorMessage = "Parameter error : number of folders can't be 0";
            $returnCode = UNKNOWN;
        }
    }
    if ($np->opts->generate) {
        $clear_mdp = $np->opts->generate;
        $generatePassword = 1;
    }

    if ($np->opts->user) {
        $user = $np->opts->user;
        my $l = length($userList{$user});
        if (($l > 2)||($generatePassword > 0)) {
            ($trace)? print("DEBUG----:$fct:user = $user\n"):();
        } else {
            $errorMessage = "Parameter error : USER given is unknown";
            $returnCode = UNKNOWN;
        }
    }

    if ($np->opts->warning) {
        $warning = $np->opts->warning;
        if ($warning =~ m/^[0-9]+$/) {
            ($trace)? print("DEBUG----:$fct:warning threshold= $warning\n"):();
        } else {
            $errorMessage = "Parameter error : Warning parameter [".$warning."] must be an integer";
            $returnCode = UNKNOWN;
        }
    }
    if ($np->opts->critical) {
        $critical = $np->opts->critical;
        if ($critical =~ m/^[0-9]+$/ ) {
            ($trace)? print("DEBUG----:$fct:critical threshold= $critical\n"):();
        } else {
            $errorMessage = "Parameter error : Critical parameter [".$critical."] must be an integer";
            $returnCode = UNKNOWN;
        }
    }

    if ($np->opts->disposition) {
        $disposition = $np->opts->disposition;
    }

    return($returnCode);
}

#--------------------------------------------------------------------------------------#
#                                 END processCallParameters                            #
#--------------------------------------------------------------------------------------#

#--------------------------------------------------------------------#
# Add performance data into the nagios return message                #
#--------------------------------------------------------------------#
sub addPerformanceData {
    my $label = $_[0];
    my $value = $_[1];
    my $unite = $_[2];
    my $warn  = $_[3];
    my $crit  = $_[4];

    $np->add_perfdata(
        label => $label,
        value => $value,
        uom => $unite,
        threshold => 1,
        warning => $warn,
        critical => $crit,
    );
}



#--------------------------------------------------------------------#
# returns encrypted password from a given string (uncrypted password)#
#--------------------------------------------------------------------#
sub encryptString {
   my $string = shift;

   my $cipher = Crypt::CBC->new(
      -key        => $KEY,
      -cipher     => 'Blowfish',
      -padding  => 'space',
      -add_header => 1
   );

   my $enc = $cipher->encrypt( $string  );
   return $enc;
}

#--------------------------------------------------------------------#
# returns decrypted password from a given string (crypted password)  #
#--------------------------------------------------------------------#
sub decryptString {
   my $string = shift;

   my $cipher = Crypt::CBC->new(
      -key        => $KEY,
      -cipher     => 'Blowfish',
      -padding  => 'space',
      -add_header => 1
   );

   my $dec = $cipher->decrypt( $string  );
   return $dec;
}

#--------------------------------------------------------------------#
# Record couple {user,crypted_password} in the mdp file              #
# this file is used to connect the user to the mailbox               #
#--------------------------------------------------------------------#
sub recordMdp {
    my $u = shift;
    my $p = shift;
    my $res = open(OUT,">>$ficMdp");
    if ($res != null) {
        my $enc = encryptString( $p );
        my $mime = encode_base64($enc);
        print OUT "$u".";".$mime;
        chomp($mime);
        print("couple($u;$mime): recorded successfully\n");
    } else {
        print("Error while opening file : $ficMdp : $!\n");
    } 
    close(OUT);
}

#--------------------------------------------------------------------#
# Load file mdp within userList hash table (global variable)         #
#--------------------------------------------------------------------#
sub loadUserList {
    my $u = "";
    my $p = "";
    my $res = open(IN,"$ficMdp");
    if ($res != null) {
        while (<IN>) {
            chomp;
            ($u,$p) = split(/;/,$_);
             ($trace)? print("u=$u, p=$p\n"):();
             $userList{$u} = $p;
        }
    } else {
        print("Erreur ouverture fichier : $!\n");
    }
    close(IN);
}

#--------------------------------------------------------------------#
# Check mailbox connect time. If connect time is over limits, raise  #
# an approriate alarm                                                #
#--------------------------------------------------------------------#
sub checkResponseTime {
    my $responseTime = shift;
    
    if ($responseTime >= $critical) {
        $cr = $STATE_CRITICAL;
        $message = $messagesTextFr{'responseTime'}." [".$responseTime."] ".$messagesTextFr{'overCritical'}." [".$critical."]";
    } elsif ($responseTime >= $warning) {
        $rc = $STATE_WARNING;
        $message = $messagesTextFr{'responseTime'}." [".$responseTime."] ".$messagesTextFr{'overWarning'}." [".$warning."]";
    } else {
        $rc = $STATE_OK;
        $message = $messagesTextFr{'underThreshold'};
    }
    return($rc);
}
#--------------------------------------------------------------------#
# Perform the indicator calculation                                  #
#  1 - Establish a SSL connection with the mail server               #
#  2 - Connect to the mailbox                                        #
#  3 - Calculate connection establishment delay                      #
#  4 - Read each folder and count mails                              #
#      a - Build a performance record                                #
#      b - Compare with limits and raise appropriate alarm           #
#--------------------------------------------------------------------#
sub performCheck {
    my $login = shift;
    my $returnCode = $STATE_OK;
    #-----------Mail ports----------------#
    # POP3 - port 110                     #
    # IMAP - port 143                     #
    # SMTP - port 25                      #
    # HTTP - port 80                      #
    # Secure SMTP (SSMTP) - port 465      #
    # Secure IMAP (IMAP4-SSL) - port 585  #
    # IMAP4 over SSL (IMAPS) - port 993   #
    # Secure POP3 (SSL-POP) - port 995    #
    #-------------------------------------#
    my $port = 993;
    my $startRequest = [gettimeofday];
    #----------------------------------------------------------------#
    # 1 - Establish a SSL connection with the mail server.           #
    # This connection needs a valid certificate (not delivered with  #
    # this plugin for confidential reasons)                          #
    #----------------------------------------------------------------#
    if ($ssl) {
        BEGIN {
            IO::Socket::SSL::set_ctx_defaults(
                verify_mode => Net::SSLeay->VERIFY_PEER(),
                ca_file => "/etc/ssl/certs/ca-certificates.crt",
                # ca_path => "/alternate/path/to/cert/authority/directory"
            );
        }
    }

    ($trace)? print("mailserver=$mailServer, port=$port, user=$login, passwd=$userList{$login}\n"):();
    my $socket = IO::Socket::SSL->new(
                PeerAddr => $mailServer,
                PeerPort => $port,
                SSL_version =>'SSLv2/3',
                Proto    => 'tcp'); #|| die "Error : ".IO::Socket::SSL::errstr();
    if ($socket == null) {
                $message = "Connection error : ".IO::Socket::SSL::errstr();
                $returnCode = $STATE_CRITICAL;
                return($returnCode);
    }
    #----------------------------------------------------------------#
    # 2 - Establish a IMAPS connection with the mail server.         #
    # This connection needs a valid user and password                #
    #----------------------------------------------------------------#
    my $imap = Mail::IMAPClient->new( Server  => $mailServer,
                               Port => $port,
                               Ssl => 1,
                               User    => $login,
                               Debug => 0,
                               Password  => decryptString( decode_base64($userList{$login})));
    if ($imap == null) {
        $message = "Imap connect error : IMAP Failure :".$@;
        $returnCode = $STATE_CRITICAL;
        return($returnCode);
    }
    #----------------------------------------------------------------#
    # 3 - Calculate mailbox connection establishment time and raise  #
    # appropriate alarm if necessary.                                #
    #----------------------------------------------------------------#
    
    my $endRequest = [gettimeofday];
    my $elapsedTime = tv_interval ( $startRequest, $endRequest);
    my $label = "mailboxAccess";
    my $state = 0;
    my $unit = "ms";
    my $responseTime = $elapsedTime*1000;
    $responseTime = sprintf("%d",$responseTime);
    addPerformanceData($label,$responseTime,$unit,$warning_cnx,$critical_cnx);

    #----------------------------------------------------------------#
    # 4 - Read each folder, count mail and raise appropriate alarm   #
    # if necessary.                                                  #
    #----------------------------------------------------------------#
    foreach my $box (@folders) {
       # How many msgs are we going to process
       $label = $box;
       $unit = "";
       if ($disposition eq 'P') {
           $unreadMails = $imap->message_count($box);
       } else {
           $unreadMails = $imap->unseen_count($box);
       }
       addPerformanceData($label,$unreadMails,$unit,$warning,$critical);
       if ($unreadMails >= $critical) {
           $returnCode=$STATE_CRITICAL;
           $message = $message."[C:".$box."=".$unreadMails."]";
       } elsif ($unreadMails >= $warning) {
           $returnCode=$STATE_WARNING;
           $message = $message."[W:".$box."=".$unreadMails."]";
       } else {
       }
    }
    $imap->logout();
    return($returnCode);
}



#MAIN---------------------------------------------------------------------#
#                  #     #    #      ###   #     #                        #
#                  ##   ##   # #      #    ##    #                        #
#                  # # # #  #   #     #    # #   #                        #
#                  #  #  # #     #    #    #  #  #                        #
#                  #     # #######    #    #   # #                        #
#                  #     # #     #    #    #    ##                        #
#                  #     # #     #   ###   #     #                        #
#-------------------------------------------------------------------------#
loadUserList();
my $rc1 = defineCallParameters();
my $rc2 = processCallParameters();
if ($rc2 != $STATE_OK) {
    $np->nagios_exit( $rc2, $errorMessage);
}

if($generatePassword > 0) {
    recordMdp($user,$clear_mdp);
    exit(0);
}
my $rc3 = performCheck($user);
$np->nagios_exit( $rc3, $message);
########## END ############
