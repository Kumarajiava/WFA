#! c:\perl\bin\perl.exe
#------------------------------------------
# FRUC
# CLI client for Forensics Server Project First Responder Utility
#
# ChangeLog
# 06/06/2006 - v 1.2  Updated how the commands are sent to and processed
#              by the frucjob helper utility; Modified the delimiter in
#              configuration file in order to avoid issues with the delimiter
#              being used in the commandline 
# 08/01/2005 - v 1.1a Updated how external commands are
#              run; specifically, they need to be run in the
#              order specified in the INI file, and a time limit
#              needed to be added in case the processes got hung up
#              For this second change, Win32::Job is used
#
# copyright 2007 H. Carvey keydet89@yahoo.com
#------------------------------------------
use lib '.';
use lib './lib';
use lib './site/lib';
use strict;
use Win32::TieRegistry(Delimiter=>"/");
use Win32::OLE qw(in);
use Getopt::Long;
use IO::Socket;
use Win32::API::Prototype;
use Config::INIFiles;

#------------------------------------------
# Setup the necessary API calls for use in
# getting Registry key LastWrite times
#------------------------------------------
ApiLink('kernel32.dll', 
        'BOOL  FileTimeToLocalFileTime(FILETIME *lpFileTime, 
                             LPFILETIME lpLocalFileTime )' ) 
    || die "Can not locate FileTimeToLocalFileTime()";

ApiLink('kernel32.dll', 
        'BOOL  FileTimeToSystemTime(FILETIME *lpFileTime, 
                             LPSYSTEMTIME lpSystemTime )' ) 
    || die "Can not locate FileTimeToSystemTime()";

#------------------------------------------
# Global Settings
#------------------------------------------
my $VERSION = '1.2';
my $error;

#------------------------------------------
# Parse arguments
#------------------------------------------
my %config;
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(server|s=s port|p=s file|f=s verbose|v encrypt|e=s help|?|h));

print "Verbose mode set.\n" if ($config{verbose});

if ($config{help} || !%config) {
	print STDERR "You must enter a valid config file to use, dude.\n\n";
	\_syntax();
	exit 1;
}

if (!$config{file}) {
	print "You must enter a valid config file to use, dude.\n\n";
	exit 1;
}

if (-e $config{file}) {
}
else {
	print "Config file not found, dude.\n\n";
	exit 1;
}

#------------------------------------------
# Parse ini file
#------------------------------------------
my $cfg = Config::IniFiles->new(-file => $config{file});
if (! $cfg->SectionExists('Configuration')) {
	print STDERR $config{file}." does not contain a Configuration section, dude.\n";
	exit 1;
}

# Load configuration settings, and adjust based on CLI args
my %ini;
tie %ini, 'Config::IniFiles', (-file => $config{file});
my %settings = %{$ini{'Configuration'}};
$settings{server}   = $config{server} if ($config{server});
$settings{port}     = $config{port} if ($config{port});
$settings{name}     = Win32::NodeName();
#------------------------------------------
# Load entries in the ini file
#------------------------------------------
my %regvals = %{$ini{'Registry Values'}};
my %regkeys = %{$ini{'Registry Keys'}};
my %commands = %{$ini{'Commands'}};

#------------------------------------------
# Launch _main()
#------------------------------------------
\_main();

#------------------------------------------
# Subroutines section
#------------------------------------------

#------------------------------------------
# _syntax()
# Print out help menu if command line arguments
# are used
#------------------------------------------
sub _syntax {
print<< "EOT";
FRUC v 1.2 [-s server IP] [-p port] [-f ini file] [-h]
First Responder Utility (CLI) v.$VERSION, data collection utility
of the Forensics Server Project 

  -s system......IP address of Forensics Server
  -p port........Port to connect to on the Forensics Server
  -f file........Ini file to use (use other options to 
                 override ini file configuration settings)
  -v.............Verbose output (more info, good for monitoring 
                 activity)               
  -h.............Help (print this information)
  
Ex: C:\\>fruc -s <IP Address> -p <port> -f <ini file>
  
copyright 2004-2006 H. Carvey
EOT
}

#-------------------------------------------------------------	
# _sendData()
# Sends data to the server using the DATA verb
# Use to send 
#-------------------------------------------------------------
sub _sendData {
	my $filename = $_[0];
	my $data = $_[1];
	my $line;
	my $conn = new IO::Socket::INET (PeerAddr => $settings{server},
                                   PeerPort => $settings{port},
                                   Proto => 'tcp');
             
	if (!$conn) {
		$error = "Error setting up socket: $!";
		return 0;	
	}
	$conn->autoflush(1); 	
	$conn->send("DATA $filename\n");
#	print "DATA command sent.\n";
	if ($conn->recv($line, 256)) {
		if ($line =~ m/^OK$/i) {
#			print "OK received.\n";
	  	$conn->send($data."\n");
#			print "Data sent.\n";
		}
	}	
	close($conn);
	return 1;
}
#-------------------------------------------------------------	
# _sendCloseLog()
#-------------------------------------------------------------
sub _sendCloseLog {
	my $line;
	my $conn = new IO::Socket::INET (PeerAddr => $settings{server},
                                   PeerPort => $settings{port},
                                   Proto => 'tcp');
             
	if (!$conn) {
		$error = "Error setting up socket: $!";
		return 0;	
	}
	$conn->autoflush(1); 	
	$conn->send("CLOSELOG ".localtime(time));
#	&_addString("CLOSELOG command sent.");
	close($conn);
	return 1;
}

#-------------------------------------------------------------	
# _sendLog()
#-------------------------------------------------------------
sub _sendLog {
	my $msg = $_[0];
	my $line;
	my $conn = new IO::Socket::INET (PeerAddr => $settings{server},
                                   PeerPort => $settings{port},
                                   Proto => 'tcp');
             
	if (!$conn) {
		$error = "Error setting up socket: $!";
		return 0;	
	}
	$conn->autoflush(1); 	
	$conn->send("LOG ".$msg);
	close($conn);
	return 1;
}

#------------------------------------------------------------
# _getRegKeyValue()
# Get a single Registry key value
#------------------------------------------------------------
sub _getRegKeyValue {
	my $key = $_[0];
	my $val = $_[1];
	my $conn;
	my $hive = (split(/\\/,$key))[0];
	$key =~ s/^$hive\\//;
	$key =~ s/\\/\//g;
	
	$hive = "LMachine" if ($hive eq "HKLM");
	$hive = "CUser" if ($hive eq "HKCU");
	
	if (my $reg = $Registry->{$hive}) {
		if ($conn = $reg->{$key}) {
			
			my @values = $conn->ValueNames();
			if (grep(/^$val/i,@values)) {
				my $value = $conn->GetValue($val);
				return $value;
			}
			else {
				return "$val value not found.";
			}
		}
		else {
			return "Error: ".Win32::FormatMessage Win32::GetLastError."\n";
		}
	}
	else {
		my $err = Win32::FormatMessage Win32::GetLastError;
		return "Error connecting to Registry: $err\n";
	}
}

#------------------------------------------------------------
# _getRegKeyValues()
# Get an array containing Registry key value names
#------------------------------------------------------------
sub _getRegKeyValues {
	my $key = $_[0];
	my $conn;
	my $hive = (split(/\\/,$key))[0];
	$key =~ s/^$hive\\//;
	$key =~ s/\\/\//g;
	
	$hive = "LMachine" if ($hive eq "HKLM");
	$hive = "CUser" if ($hive eq "HKCU");
	
	if (my $reg = $Registry->{$hive}) {
		if ($conn = $reg->{$key}) {
			my @values = $conn->ValueNames();
			return @values;
		}
		else {
			return "Error: ".Win32::FormatMessage Win32::GetLastError."\n";
		}
	}
	else {
		my $err = Win32::FormatMessage Win32::GetLastError;
		return "Error connecting to Registry: $err\n";
	}
}

#------------------------------------------------------------
# _external()
# Run external commands; send command into subroutine, return
# output of command in a string
#------------------------------------------------------------
sub _external {
	my $cmd = $_[0];
	my @resp;
	
	my $tag = (split(/\s/,$cmd))[0];
	$tag = $tag.".exe" unless ($tag =~ m/\.exe$/);
  return "Error: $tag Not Found" unless (-e $tag);
  
	eval {
		@resp = `frucjob.exe $cmd`;
	};
	($@) ? (return $@) : (return (join("",@resp)));
}

#------------------------------------------------------------
# _getKeyTime()
# 
#------------------------------------------------------------
sub _getKeyTime {
	my $key = $_[0];
	my $conn;
	my $hive = (split(/\\/,$key))[0];
	$key =~ s/^$hive\\//;
	$key =~ s/\\/\//g;
	
	$hive = "LMachine" if ($hive eq "HKLM");
	$hive = "CUser" if ($hive eq "HKCU");
	
	my @month = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
	my @day = qw/Sun Mon Tue Wed Thu Fri Sat/;
	
	my %info;
	my $remote;
# Registry key to check
	if (my $reg = $Registry->{$hive}) {
		if ($conn = $reg->{$key}) {
			%info = $conn->Information();
		}
		else {
			return "Error: ".Win32::FormatMessage Win32::GetLastError."\n";
		}
	}
	else {
		my $err = Win32::FormatMessage Win32::GetLastError;
		return "Error connecting to Registry: $err\n";
	}
	my $pFileTime = $info{'LastWrite'};
# Credit goes to Ian Brown <ibrown@mitchellandmitchell.com> with locating
# a buffer overflow issue b/c $lpLocalFileTime was not set up initially
	my $lpLocalFileTime = pack ("L2", 0);
# Create an empty SYSTEMTIME structure of 8 short ints
# pack()'d together
	my $pSystemTime = pack("S8", 0);
# Translate the FILETIME to LOCALFILETIME
	if (FileTimeToLocalFileTime($pFileTime,$lpLocalFileTime)) {
# call FileTimeToSystemTime()
		if (FileTimeToSystemTime($lpLocalFileTime,$pSystemTime)) {
# Unpack the 8 WORD values from the system time structure....
# year,month,dayofweek,day,hour,minute,sec,milli
  		my @time = unpack("S8", $pSystemTime);
  
  		$time[5] = "0".$time[5] if ($time[5] =~ m/^\d$/);
  		$time[6] = "0".$time[6] if ($time[6] =~ m/^\d$/);
  		my $timestr = $day[$time[2]]." ".$time[1]."/".$time[3]."/".$time[0].
                " ".$time[4].":".$time[5].":".$time[6].".".$time[7];
  		return "$timestr";
		}
		else {
			
		}
	}
	else {
		
	}
}

#------------------------------------------------------------
# _main()
# This is the primary driver routine for the script; ties 
# everything else together
#------------------------------------------------------------
sub _main() {
	my $start = time();

# This is one of the changes specified for version 1.1a
# The commands need to be run in the order specified in the
# INI file; the below code does that
	my $delimiter = "::";
	my @sorted = sort {$a <=> $b}(keys %commands);
	foreach (@sorted) {
#		print "-" x 50,"\n";
		my ($exe,$file) = split(/$delimiter/,$commands{$_},2);
		my $results = _external($exe);
# Send log entry giving command run and time.
		my $cmdtime = localtime(time);
		if (_sendLog("[$cmdtime] $exe")) {
			print "\"[$cmdtime] $exe\" log command sent.\n" if ($config{verbose});
		}
		else {
			if ($config{verbose}) {
				print "\"[$cmdtime] $exe\" log command sent.\n";
				print "$error.\n";
			}
		}
# Send results		
		if (_sendData($settings{name}."-$file",$results)) {
			print "$exe results data sent.\n" if ($config{verbose});
		}
		else {
			print "$exe results data not sent.\n" if ($config{verbose});
		}
	}
		
# Send Registry keys to file "RegistryKeys.dat"
	my @registrykeys;
	foreach my $r (keys %regkeys) {
		my $t = _getKeyTime($regkeys{$r});
		if ($t =~ m/^Error/i) {
			print "$regkeys{$r} not found \n\n" if ($config{verbose});
			next;
		}
		else {
#			print "$regkeys{$r}\n";
		}
		push(@registrykeys,"$regkeys{$r};$t");
		my @values = _getRegKeyValues($regkeys{$r});
		foreach my $val (@values) {
			my $value = _getRegKeyValue($regkeys{$r},$val);
#			print "\t$val => $value\n";
			push(@registrykeys,"\t$val;$value");
		}
	}
	my $reg = join("\n",@registrykeys);
	if (_sendData(Win32::NodeName()."-regkeys\.dat",$reg)) {
		print "Registry Keys data sent.\n";
	}
# Send Registry key values to file "RegistryValues.dat"
	my @regvalues;
	foreach my $k (keys %regvals) {
		my ($key, $val) = split(/;/,$regvals{$k},2);
		my $t = _getKeyTime($key);
		if ($t =~ m/^Error/i) {
			print STDERR "$key not found.\n\n" if ($config{verbose});
			next;
		}
		else {
#			print "$key\n";
		}
		my $value = _getRegKeyValue($key, $val);
		$val = "(Default)" if ($val eq "");
		push(@regvalues,"$key;$t;$val;$value");
	}
	my $reg = join("\n",@regvalues);
	if (_sendData(Win32::NodeName()."-regvals\.dat",$reg)) {
		print "Registry Values data sent.\n";
	}
	my $endtime = time();
	my $completed = (($endtime - $start)/1000);
	\_sendLog("FRU completed in ".$completed." seconds.");
	print "FRU completed in ".$completed." seconds.\n" if ($config{verbose});
# When all other activities have been completed, send the 
# CLOSELOG command
	&_sendCloseLog();
# DONE
	print "CloseLog command sent.  Thank you for playing.\n" if ($config{verbose});
}
