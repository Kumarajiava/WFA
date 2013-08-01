#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------
# fspc.pl
# Server code for Forensics Server Project; Acts as a forensic data
# collection server
# 
# Version 1.0c
#
# Verbs: FILE, DATA, LOG, CLOSELOG
#
# copyright 2006 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------------
use lib '.';
use lib './lib';
use lib './site/lib';
#use strict;
use IO::Socket;
use Digest::MD5;
use Digest::SHA1;
use Getopt::Long;

#--------------------------------------------------------------------------
# Globals
my %setup;
my $VERSION = '1.0c';

#------------------------------------------
# Parse arguments
#------------------------------------------
my %config;
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(casedir|d=s port|p=s casename|n=s verbose|v inv|i=s 
                        close|c logfile|l=s help|?|h));

print "Verbose mode set.\n" if ($config{verbose});

if ($config{help} || !%config) {
	\_syntax();
	exit 1;
}

$setup{basedir} = Win32::GetCwd();
$setup{casedir} = $config{casedir} || "cases";
$setup{casename} = $config{casename};
$setup{port} = $config{port} || 7070;
$setup{investigator} = $config{inv};
$setup{logfile} = $config{logfile} || "case\.log";
&_setup();
\_main();

#------------------------------------------
# _syntax()
# Print out help menu if command line arguments
# are used
#------------------------------------------
sub _syntax {
print<< "EOT";
FSPC [-d case dir] [-n case name] [-p port] [-i investigator] 
     [-l logfile] [-c] [-v] [-h]
Forensic Server Project (CLI) v.1.0c, server component of the 
Forensics Server Project 

  -d case dir....Case directory (default: cases)
  -n case name...Name of the current case
  -i invest......Investigator\'s name
  -p port........Port to listen on (default: 7070)
  -l logfile.....Case logfile (default: case.log)
  -v.............Verbose output (more info, good for monitoring 
                 activity)               
  -c.............Close FSP after CLOSELOG command sent (best used 
                 when collecting data from only one system)               
  -h.............Help (print this information)
  
Ex: C:\\>fspc -d cases -n testcase -i \"H. Carvey\"
    C:\\>fspc -n newcase -p 80
  
copyright 2006 H. Carvey
EOT
}

#--------------------------------------------------------------------------
# Case Management section
sub _main {
# Use Win32::GetCwd to get the directory that the
# server is in.  _setup() will call Win32::SetCwd.
	$setup{basedir} = Win32::GetCwd;
	$setup{basedir}."\\" unless ($setup{basedir} =~ m/\\$/);
	$setup{casedir}."\\" unless ($setup{casedir} =~ m/\\$/);
	$setup{casename}."\\" unless ($setup{casename} =~ m/\\$/);

	if ($config{verbose}) {
		print "Case Name: ".$setup{casename}."\n";
		print "Port     : ".$setup{port}."\n";	
	}
	
# Variable for client connection
	my $client;
# For testing, restrict to a specific IP address
# Need to implement this in the GUI in future versions
#my @conn = ('127.0.0.1');
	my $server = new IO::Socket::INET (LocalPort => $setup{port},
                                 Proto => 'tcp',
                                 Listen => SOMAXCONN,
                                 Reuse => 1);
	die "Could not create socket: $!\n" unless $server;
	print "Server started...\n";
	&_log("Server started");
	&_log("-------------------------------------------------------------");
	&_log("Case = ".$setup{casename});
	&_log("Investigator = ".$setup{investigator});
	&_log("-------------------------------------------------------------");
	print "Awaiting connection...\n";
	my %conns;
	while (1) {
		if ($client = $server->accept()) {
			$client->autoflush(1);
			my $peer = $client->peerhost;
			print "Connection from $peer\n" unless $conns{$peer};
			$conns{$peer} = 1;
# Handle connection
			my $input="";
			$client->recv($input,256);
# Handle a FILE command.  This command initiates a connection
# for copying file contents.  
			if ($input =~ m/^FILE/i) {
				chomp($input);
				my $bin;
				my $len;
				my $written;
				my $offset;
				my $blksize = 2048;
# Need to read in the binary contents of the file
				my $file = (split(/\s/,$input,2))[1];
				print "FILE command received: $file\n" if ($config{verbose});
				&_log("FILE command received: $file");
#				my $filename = "$file\.fsp";
				my $filename = "$file";
				my @list = split(/\./,$file);
				my $datfile = $list[0].".dat";
			
				open(FH2,"> $filename") || die "Could not open $file.fsp: $!\n";
				binmode(FH2);
				print "$filename created and opened.\n" if ($config{verbose});
				&_log("$filename created and opened.");
				$client->send("OK");
				while ($len = sysread($client,$bin,$blksize)) {
					die "System read error: $!\n" unless (defined $len);
					$offset = 0;
					while ($len) {
						$written = syswrite(FH2,$bin,$len,$offset);
						die "System write error: $!\n" unless (defined $written);
						$offset += $written;
						$len -= $written;
					}
				}
				close(FH2);
				&_log("$filename closed. Size ".(stat($filename))[7]);
# need to confirm hashes here
				&confirmHashes($filename,$datfile);
			}
#-----------------------------------------------------------------
# Handle DATA commands
# Receive data, write to a file
			elsif ($input =~ m/^DATA/i) {
				chomp($input);
				my $file = (split(/\s/,$input,2))[1];
				print "DATA command received: $file\n" if ($config{verbose});
				&_log("DATA command received: $file");
				$client->send("OK");
				my $data;
			
				open(FH,"> $file") || &_log("$file could not be opened: $!");
				while (defined ($data=<$client>)) {
					print FH $data;
				}
				close(FH);
				my ($md5,$sha1) = hash($file);
				&_log("HASH ".$file.":".$md5.":".$sha1);
			}
#-----------------------------------------------------------------
# Receive log entries externally		
# Client can send information to be logged
			elsif ($input =~ m/^LOG/i) {
				my $msg = (split(/\s/,$input,2))[1];
				&_log("LOG ".$msg);
			}
#-----------------------------------------------------------------
# Receive CLOSELOG command		
# Hash the caselog file 			
			elsif ($input =~ m/^CLOSELOG/i) {
				&_log("CLOSELOG command received.");
				print "CLOSELOG command received.\n" if ($config{verbose});
				&_log("-------------------------------------------------------------");
				print "-------------------------------------------------------------\n";
				my($md5,$sha1) = hash($setup{logfile});
				open(FH,"> caselog.hash");
				print FH $md5.":".$sha1."\n" if ($config{verbose});
				close(FH);
				if ($config{close}) {
					print STDERR "\n";
					print STDERR "Shutting down the Forensic Server...\n";
					exit 1;
				}
			}
			else {
# log command unknown		
# Should never see this, but it's always possible
				&_log("Command unknown: $input");	
			}
		}
	}
}

#------------------------------------------
# _log()
# Logging subroutine
# File separator = ; (for analysis)
#------------------------------------------
sub _log {
	open(FH,">>".$setup{logfile});
	print FH localtime(time).";".$_[0]."\n";
	close(FH);
}

#------------------------------------------
# hash subroutine
# used by client, and by server to verify
#------------------------------------------
sub confirmHashes {
	my $filename = $_[0];
	my $datfile = $_[1];
	my ($md5,$sha1);
# Get hashes from datfile
	open(FH,$datfile) || &_log("Could not open $datfile: $!");
	while (<FH>) {
		chomp;
		if ($_ =~ m/^md5/i) {
			$md5 = (split(/:/,$_,2))[1];
		}
		elsif ($_ =~ m/^sha1/i) {
			$sha1 = (split(/:/,$_,2))[1];
		}
		else {
# Nothing to do			
		}
	}
	
# Compute hashes for copied file		
	my ($md52,$sha12) = hash($filename);
	
	if ($md5 eq $md52) {
		&_log("MD5 hashes confirmed for $filename.");
	}
	else {
		&_log("MD5 hashes NOT confirmed for $filename.");
		print "Original MD5: $md5\n" if ($config{verbose});
		print "New MD5     : $md52\n" if ($config{verbose});
	}
	
	if ($sha1 eq $sha12) {
		&_log("SHA-1 hashes confirmed for $filename.");
	}
	else {
		&_log("SHA-1 hashes NOT confirmed for $filename.");
		print "Original SHA1: $sha1\n" if ($config{verbose});
		print "New SHA1     : $sha12\n" if ($config{verbose});
	}
}

#------------------------------------------
# hash subroutine
# used by client, and by server to verify
#------------------------------------------
sub hash {
	my $file = $_[0];
	my $md5;
	my $sha;
	eval {
		open(FILE, $file);
  	binmode(FILE);
		$md5 = Digest::MD5->new->addfile(*FILE)->hexdigest;
		close(FILE);
	
		open(FILE, $file);
  	binmode(FILE);
		$sha = Digest::SHA1->new->addfile(*FILE)->hexdigest;
		close(FILE);
	};
	($@) ? (return $@) : (return ($md5,$sha));
}

#------------------------------------------
# setup subroutine
# used to setup a new case; needs to be available
# remotely
#------------------------------------------
sub _setup {
# clean up the directory names
	$setup{basedir} = $setup{basedir}."\\" unless ($setup{basedir} =~ m/\\$/); 
	$setup{casedir} = $setup{casedir}."\\" unless ($setup{casedir} =~ m/\\$/);
	$setup{casename} = $setup{casename}."\\" unless ($setup{casename} =~ m/\\$/);
	my $casedir = $setup{basedir}.$setup{casedir};
	mkdir $casedir if (! -e $casedir && ! -d $casedir);
	my $curr_case = $casedir.$setup{casename};
	mkdir $curr_case if (! -e $curr_case && ! -d $curr_case);
	Win32::SetCwd($curr_case);
	print "Setup complete.\n" if ($config{verbose});
}

#------------------------------------------
# reset subroutine
# clears setup data so it can be renewed
#------------------------------------------
sub _reset {
	Win32::SetCwd($setup{basedir});
}
