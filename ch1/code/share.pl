#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# share.pl - Perl script to retrieve share information
#            Allows for checking of remote hosts
#
# Usage: C:\perl>share.pl 
#        C:\perl>share.pl <host> <username> <password>
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
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

my %types = (0x00 => "Disk Drive",
						 0x01 => "Print Queue",
             0x02 => "Device",
             0x03 => "IPC",
             0x80000000 => "Disk Drive Admin",
             0x80000001 => "Print Queue Admin",
             0x80000002 => "Device Admin",
             0x80000003 => "IPC Admin");

my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($config{server},'root\cimv2',$config{user},$config{passwd}) 
	|| die "Error connecting to $config{server}: ".Win32::OLE->LastError()."\n";

foreach my $share (in $serverObj->InstancesOf("Win32_Share")) {
	
	my $name;
	($share->{Name} eq $share->{Caption}) ? ($name = $share->{Name}) :
		($name = $share->{Name}." (".$share->{Caption}.")");
	my $type   = $types{$share->{Type}};
	my $path   = $share->{Path};
	my $status = $share->{Status};
	
	if ($config{csv}) {
		print "$name,$type,$path,$status\n";
	}
	else {
		print  "Name        -> $name\n";
		print  "Type        -> $type\n" if ($type);
		print  "Path        -> $path\n" if ($path);
		print  "Status      -> $status\n" if ($status);
		print  "Max Users   -> ".$share->{MaximumAllowed}."\n" if (!$share->{AllowMaximum});
		print "\n";
	}
}

sub _syntax {

	print<< "EOT";
Share [-s system] [-u username] [-p password] [-h]
Collect share information from local\\remote Windows systems.

  -s system......Name of the system to scan
  -u username....Username used to connect to the remote system (usually
	               an Administrator)
  -p password....Password used to connect to the remote system
  -c.............Comma-separated (.csv) output (open in Excel)
  -h.............Help (print this information)
  
Ex: C:\\>share -s <server> -u <username> -p <password>
  
copyright 2007 H. Carvey
EOT
}