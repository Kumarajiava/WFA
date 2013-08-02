#! c:\perl\bin\perl.exe
#------------------------------------------------------
# evtstats.pl
# Perl script to parse the contents of Event Log files and 
#   display statistics
#
# usage: evtstats.pl <path to EVT file>
# 
# NOTE: Requires the use of the File::ReadEvt module 
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------

use strict;
use File::ReadEvt;

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

my $size = (stat($file))[7];

my $evt = File::ReadEvt::new($file);
my %hdr = ();
if (%hdr = $evt->parseHeader()) {
	print "Max    Size of the Event Log file            = ".$hdr{maxsize}." bytes\n";
	print "Actual Size of the Event Log file            = ".$size." bytes\n";
	print "Total number of event records (header info)  = ".($hdr{nextID} - $hdr{oldestID})."\n";
}
else {
	print "Error : ".$evt->getError()."\n";
	die;
}

my $ofs = $evt->getFirstRecordOffset();

# maintain stats
my $count = 0;
my %types = ();
my %ids   = ();
my %sources = ();
my %computer_names = ();
my @recnum = ();

while ($ofs) {

	my %record = $evt->readEventRecord($ofs);
#	print "-----------------------------------------------\n";
#	foreach my $r (keys %record) {
#		print "$r -> $record{$r}\n";
#	}
#	print "-----------------------------------------------\n";
#	printf "Current Offset = 0x%x\n",$evt->getCurrOfs();

# Populate statistics
	$count++;
	$types{$record{evt_type}}++;
	$sources{$record{source}}++;
	$computer_names{$record{computername}}++;
	$ids{$record{evt_id}}++;
	push(@recnum,$record{rec_num});
	
# length of record is $record{length}...skip forward that far
	$ofs = $evt->locateNextRecord($record{length});
#	printf "Current Offset = 0x%x\n",$evt->getCurrOfs();
}
$evt->close();

print "Total number of event records (actual count) = $count\n";
print "Total number of event records (rec_nums)     = ".scalar(@recnum)."\n";
#print "\n";
#printf "%-20s %-5s\n","Sources","Num";
#printf "%-20s %-5s\n","-" x 15,"-" x 3;
my $count = 0;
foreach my $s (keys %sources) {
#	printf "%-20s %-5d\n",$s,$sources{$s};
	$count += $sources{$s};
}
print "Total number of event records (sources)      = ".$count."\n";
#print "\n";
#printf "%-30s %-5s\n","Event Type","Num";
#printf "%-30s %-5s\n","-" x 25,"-" x 3;
my $count = 0;
foreach my $t (keys %types) {
#	printf "%-30s %-5d\n",$t,$types{$t};
	$count += $types{$t};
}
print "Total number of event records (types)        = ".$count."\n"; 
#print "\n";
#printf "%-10s %-5s\n","Event ID","Num";
#printf "%-10s %-5s\n","-" x 8,"-" x 3;
my $count = 0;
foreach my $id (keys %ids) {
#	printf "%-10d %-5d\n",$id,$ids{$id};
	$count += $ids{$id};
}
print "Total number of event records (IDs)          = ".$count."\n";