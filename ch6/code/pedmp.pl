#! c:\perl\bin\perl.exe
#------------------------------------------------------
# pedmp.pl
# Perl script to demonstrate the use of the File::ReadPE module
#
# Usage: pedmp.pl <filename>
#
# 
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use File::ReadPE;

my $pefile = shift || die "You must enter a filename.\n";
die "File not found.\n" unless (-e $pefile);

my $pe = File::ReadPE::new($pefile);

my %dos;
if (%dos = $pe->getDOSHeader()) {
	printf "Magic     : 0x%x\n",$dos{magic};
	printf "e_lfanew  : 0x%x\n",$dos{e_lfanew};
}
else {
	print "Error : ".$pe->getError()."\n";
}

my $tag = $pe->getNTHeader($dos{e_lfanew});

my %fh = $pe->getFileHeader($dos{e_lfanew});

my @list = $pe->getFileHeaderCharacteristics($fh{characteristics});
foreach (@list) {
	print "\t$_\n";
}
print "\n";
my $hdr = $pe->getOptionalHeaderMagic($dos{e_lfanew});
printf "Optional header magic = 0x%x\n",$hdr;
print "\n";
my %opt32 = $pe->getOptionalHeader32($dos{e_lfanew},$fh{size_opt_header});
print "\n";
map{printf "%-15s 0x%x\n",$_ ,$opt32{$_}}(keys %opt32);
print "\n";

print "Subsystem = ".$pe->getOptionalHeaderSubsystem($opt32{subsystem})."\n";

print "\n";
printf "Address of the entry point = 0x%x\n",$opt32{addr_entrypt};
print "\n";
my %dd = $pe->getImageDataDirectories($dos{e_lfanew},$opt32{rva_num});
print "Data Directories\n";
printf "%-20s %-10s %-10s\n","Name","RVA","Size";
foreach my $d (keys %dd) {
	printf "%-20s 0x%08x 0x%08x\n",$d,$dd{$d}{rva},$dd{$d}{size};
}
print "\n";
my $sections_offset = $dos{e_lfanew} + 24 + 96 + (8*$opt32{rva_num});
my %sections = $pe->getImageSectionHeaders($sections_offset,$fh{number_sections});
print "Sections\n";
foreach my $sect (keys %sections) {
	print "Name: $sect\n";
	printf "Virtual Size   : 0x%08x\n",$sections{$sect}{virt_sz};
	printf "Virtual Addr   : 0x%08x\n",$sections{$sect}{virt_addr};
	printf "Raw Data Offset: 0x%08x\n",$sections{$sect}{rdata_ptr};
	printf "Raw Data Size  : 0x%08x\n",$sections{$sect}{rdata_sz};
	printf "Characteristics: 0x%x\n",$sections{$sect}{characteristics};
	
	my @char = $pe->getImageSectionCharacteristics($sections{$sect}{characteristics});
	if (@char) {
		map{print "\t$_\n"}@char;
	}
	print "\n";
}

$pe->close();