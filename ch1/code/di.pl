#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# di.pl - Perl script to retrieve drive information
#           Allows for checking of remote hosts
#
# Usage: C:\perl>di.pl 
#        C:\perl>di.pl <host> <username> <password>
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
use strict;
use Win32::OLE qw(in);
use Getopt::Long;
my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(server|s=s user|u=s passwd|p=s csv|c help|?|h));

if ($config{help}) {
	\_syntax();
	exit 1;
}

if (! %config) {
	$config{server} = Win32::NodeName();
	$config{user}   = "";
	$config{passwd} = "";
}
$config{user} = "" unless ($config{user});
$config{passwd} = "" unless ($config{passwd});

my %types = (0 => "Unknown",
						 1 => "Root directory does not exist",
             2 => "Removable",
             3 => "Fixed",
             4 => "Network",
             5 => "CD-ROM",
             6 => "RAM");

my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($config{server},'root\cimv2',$config{user},$config{passwd}) 
	|| die "Error connecting to $config{server}: ".Win32::OLE->LastError()."\n";

if ($config{csv}) {
	
}
else {
	printf "%-8s %-11s %-12s %-25s %-12s\n","Drive","Type","File System","Path","Free Space";
	printf "%-8s %-11s %-12s %-25s %-12s\n","-" x 5,"-" x 5,"-" x 11,"-" x 5,"-" x 10;
}
foreach my $drive (in $serverObj->InstancesOf("Win32_LogicalDisk")) {
	
	my $dr    = $drive->{DeviceID};
	my $type  = $types{$drive->{DriveType}};
	my $fs    = $drive->{FileSystem};
	my $path  = $drive->{ProviderName};
	my $freebytes;
	my $tag;
	my $kb = 1024;
	my $mb = $kb * 1024;
	my $gb = $mb * 1024;
	if ("" ne $fs) {
		my $fb = $drive->{FreeSpace};
		if ($fb > $gb) {
			$freebytes = $fb/$gb;
			$tag = "GB";
		}
		elsif ($fb > $mb) {
			$freebytes = $fb/$mb;
			$tag = "MB";
		}
		elsif ($fb > $kb) {
			$freebytes = $fb/$kb;
			$tag = "KB";
		}
		else {
			$freebytes = 0;	
		}
	}
	if ($config{csv}) {
		print "$dr\\,$type,$fs,$path,$freebytes $tag\n";
	}
	else {
		printf "%-8s %-11s %-12s %-25s %-5.2f %-2s\n",$dr."\\",$type,$fs,$path,$freebytes,$tag;
	}
}

sub _syntax {

	print<< "EOT";
D(rive)I(nfo) [-s system] [-u username] [-p password] [-h]
Collect drive information from local\\remote Windows systems.

  -s system......Name of the system to scan
  -u username....Username used to connect to the remote system (usually
	               an Administrator)
  -p password....Password used to connect to the remote system
  -c.............Comma-separated (.csv) output (open in Excel)
  -h.............Help (print this information)
  
Ex: C:\\>di -s <server> -u <username> -p <password>
  
copyright 2006 H. Carvey
EOT
}