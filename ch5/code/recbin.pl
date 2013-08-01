#! c:\perl\bin\perl.exe
#------------------------------------------------------
# recbin.pl
# Perl script to parse the contents of the INFO2 file from
#   the Recycle Bin
#
# usage: recbin.pl <path to INFO2 file>
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;

my $file = shift || die "You must enter a file name.\n";
die "$file not found.\n" unless (-e $file);

my $data;
my $ofs = 0;
my $RECNUM_OFS = 264;
my $DRIVE_OFS  = 268;
my $TIME_OFS   = 272;
my $SIZE_OFS   = 280;

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);
seek(FH,$ofs,0);
read(FH,$data,16);
my @hdr = unpack("V4",$data);
$ofs += 16;

while (! eof(FH)) {
	seek(FH,$ofs,0);
	my $bytes = read(FH,$data,$hdr[3]);
# Process the record	
	my %rec = parseRecord($data);
	next if ($rec{num} == 0 && $rec{drive} == 0);
	my $t = gmtime($rec{del_time});
	printf "%-4d %-28s %-48s\n",$rec{num},$t,$rec{u_name};
	$ofs += $hdr[3];
}


close(FH);

sub parseRecord {
	my $rec = shift;
	my %record = ();
	$record{a_name} = substr($rec,4,260);
	$record{a_name} =~ s/\00//g;
	$record{num}   = unpack("V",substr($rec,$RECNUM_OFS,4));
	$record{drive} = unpack("V",substr($rec,$DRIVE_OFS,4));
	my ($t1,$t2)   = unpack("VV",substr($rec,$TIME_OFS,8));
	
	$record{del_time} = getTime($t1,$t2);
	$record{size}  = unpack("V",substr($rec,$SIZE_OFS,4));
	$record{u_name} = substr($rec,$SIZE_OFS + 4,516);
	$record{u_name} =~ s/\00//g;
	return %record;
}

#---------------------------------------------------------
# getTime()
# Get Unix-style date/time from FILETIME object
# Input : 8 byte FILETIME object
# Output: Unix-style date/time
#---------------------------------------------------------
sub getTime {
	my $lo = shift;
	my $hi = shift;
	my $t;

	if ($lo == 0 && $hi == 0) {
		$t = 0;
	} else {
		$lo -= 0xd53e8000;
		$hi -= 0x019db1de;
		$t = int($hi*429.4967296 + $lo/1e7);
	};
	$t = 0 if ($t < 0);
	return $t;
}