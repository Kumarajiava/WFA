#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# lscl.pl
# read/parse restore point change logs for data
# 
# Usage: lscl.pl <path_to_change_log>
#
# http://www.ediscovery.co.nz/wip/srp.html
#
# copyright 2006-2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
my $file = shift || die "You must enter a file name.\n";
die "$file not found.\n" unless (-e $file);

my $offset = 0;
my $data;

my %c_type = (0x01 => "Modify File",
							0x02 => "Update ACL",
							0x04 => "Update Attributes",
							0x10 => "Delete File",
							0x20 => "Create File",
							0x40 => "Rename File",
							0x80 => "Create directory",
							0x100 => "Rename directory",
							0x200 => "Delete directory",
							0x400 => "MNT-CREATE");

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);

while (<FH>) {
	seek(FH,$offset,0);
	read(FH,$data,12);
	my ($size,$type,$magic) = unpack("V3",$data);
	if ($type == 0 && $magic == 0xabcdef12) {
		seek(FH,$offset,0);
		read(FH,$data,$size);
		my $name = &parseType0($data);
		print "Original File Name : $name\n";
	}
	elsif ($type == 1 && $magic == 0xabcdef12) {
		seek(FH,$offset,0);
		read(FH,$data,$size);
		my %type1 = &parseType1($data);
		print "Sequence Number = $type1{seq}\n";
		print "Name            = $type1{name}\n";
		print "Change Type     = ".$c_type{$type1{change_type}}."\n";
	}
	elsif ($magic != 0xabcdef12) {
		
		
	}
	else {
# No other conditions		
	}
	print "\n";
	$offset += $size;
}

close(FH);

sub parseType0 {
	my $data = shift;
	my ($orig_size,$type,$magic,$preamble) = unpack("V4",substr($data,0,16));
	my ($field_len,$field_type) = unpack("V2",substr($data,16,8));
	my $name = substr($data,24,$field_len - 8);
	$name =~ s/\00//g;
	return $name;
}

sub parseType1 {
	my $data = shift;
	my %type1 = ();
	my ($orig_size,$type,$magic,$changetype) = unpack("V4",substr($data,0,16));
	my ($flags,$attr,$seq) = unpack("V3",substr($data,16,12));
#	print "\Sequence Number = $seq\n";
# Skip 36 0's
	my ($len, $type) = unpack("V2",substr($data,64,8));
	my $name = substr($data,72,$len - 8);
	$name =~ s/\00//g;
	$type1{name} = $name;
	$type1{flags} = $flags;
	$type1{attr} = $attr;
	$type1{seq}  = $seq;
	$type1{change_type} = $changetype;
	$type1{field_type} = $type;
	return %type1;
}

