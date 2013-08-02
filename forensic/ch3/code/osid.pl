#! c:\perl\bin\perl.exe
#----------------------------------------------------------------------
# OSID.pl
# Performs OS detection of a RAM dump by locating the kernel base address
# and parsing the ResourceTable from the PE file located at that address.
# 
# Version: v.0.1_20061101
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
#----------------------------------------------------------------------
use strict;
use Getopt::Long;

# parse arguments
my $file;
my $verbose = 0;
my %config;
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s verbose|v help|?|h));

if ($config{help}) {
	\_syntax();
	exit 1;
}

if (!%config && scalar(@ARGV) > 0) {
	$file = $ARGV[0];
}
elsif (!%config && scalar(@ARGV) == 0) {
	\_syntax();
	exit 1;
}

$file = $config{file} if ($config{file});
$verbose = 1 if ($config{verbose});
		
my %kb = (#0x80100000 => "NT4",
          0x80400000 => "2000",
          0x804d4000 => "XP",
          0x804d0000 => "XP",
          0x804d5000 => "XP",
          0x80a02000 => "XP",
          0x804d7000 => "XPSP2",
          0x804de000 => "2003",
          0x80800000 => "2003SP1",
          0x82000000 => "VistaBeta2",
          0x81800000 => "VistaRC1");

my $k    = 0x80000000;
my ($offset,$data);

open(FH,"<",$file) || die "Could not open $file: $!\n";
binmode(FH);

foreach my $kern (keys %kb) {
#	printf "Value = 0x%x\n",$kern;
	$offset = $kern - $k;
	my $base_addr = $offset;
	seek(FH,$offset,0);
	read(FH,$data,2);
	my $val = unpack("v",$data);
	if ($val == 0x5a4d) {
#		printf "Executable header located at 0x%x\n",$offset;
#		print "\t$kb{$kern}\n";
		
		seek(FH,$offset,0);
		read(FH,$data,0x1000);
		if (my $e_lfanew = getPEHeader($data)) {
#			printf "E_lfanew = 0x%x\n",$e_lfanew;
			
			my %ifh = getImageFileHeader($data,$e_lfanew);
#			print "Number of sections = ".$ifh{number_sections}."\n";
#			printf "Opt Header Size  = 0x%x (".$ifh{size_opt_header}." bytes)\n",$ifh{size_opt_header};
			
			my %opt32 = getImageOptionalHeader($data,$e_lfanew,$ifh{size_opt_header});
#			print  "Subsystem     : ".getOptionalHeaderSubsystem($opt32{subsystem})."\n";
#			printf "Entry Pt Addr : 0x%08x\n",$opt32{addr_entrypt};
#			printf "Image Base    : 0x%08x\n",$opt32{imagebase};
#			printf "File Align    : 0x%08x\n",$opt32{filealign};
			
#			print "\n";
			my %dd = getDataDirectories($data,$e_lfanew,$opt32{rva_num});
#			printf "%-20s %-10s %-10s\n","Data Directory","RVA","Size";
#			printf "%-20s %-10s %-10s\n","-" x 14,"-" x 3, "-" x 4;
#			foreach my $name (keys %dd) {
#				printf "%-20s 0x%08x 0x%08x\n",$name,$dd{$name}{rva},$dd{$name}{size};
#			}
# At this point, the important piece of data for what we want to do is
# $dd{'ResourceTable'}{rva}			
#			print "\n";
			my $num  = $ifh{number_sections};
			my $size = 40;
			my $ofs  = $e_lfanew + 24 + 96 + 8*$opt32{rva_num};
			my $sect = substr($data,$ofs,$num * $size);
			my %sections = getImageSectionHeaders($sect,$num);
#			printf "%-8s %-10s  %-10s  %-10s  %-10s  %-10s\n","Name","Virt Sz","Virt Addr","rData Ofs","rData Sz","Char";
#			printf "%-8s %-10s  %-10s  %-10s  %-10s  %-10s\n","-" x 4,"-" x 7,"-" x 9,"-" x 9,"-" x 8,"-" x 4;
	
			my %sec_order = ();
	
			foreach my $sec (keys %sections) {
#				printf "%-8s 0x%08x  0x%08x  0x%08x  0x%08x  0x%08x\n",$sec,$sections{$sec}{virt_sz},
				$sections{$sec}{virt_addr},$sections{$sec}{rdata_ptr},$sections{$sec}{rdata_sz},
				$sections{$sec}{characteristics};
				$sec_order{$sections{$sec}{virt_addr}} = $sec;
			}
# Now that we have the section header info, $sections{'.rsrc'}{virt_addr} 
# should be equal to $dd{'ResourceTable'}{rva}; if they are, add this 
# to the base address to get the location in the memory dump of the root
# resource directory			
#		print "\n";
#			printf "ResourceTable offset = 0x%x\n",($offset + $sections{'.rsrc'}{virt_addr});
#			print "\n";
			my $ver_ofs = getResourceInfo($offset + $sections{'.rsrc'}{virt_addr});
#			printf "The beginning of the VS_VERSIONINFO structure is located at 0x%x\n",$offset + $ver_ofs;
			
			my $descr = "NT Kernel & System";
			my %ver = getVSVerInfo($offset + $ver_ofs);
			if ($ver{FileDescription} =~ m/^$descr/i) {
				my $os = $kb{$kern};
				if ($verbose) {
					print "OS      : $os\n";
					print "Product : $ver{ProductName} ver $ver{ProductVersion}\n";
				}
				else {
					print $os."\n";
				}
			}
			else {
				print "File Description   : ".$ver{FileDescription}."\n";
				print "File Version       : ".$ver{FileVersion}."\n";
				print "Internal Name      : ".$ver{InternalName}."\n";
				print "Original File Name : ".$ver{OriginalFileName}."\n";
				print "Product Name       : ".$ver{ProductName}."\n";
				print "Product Version    : ".$ver{ProductVersion}."\n";
			}
		}			
	}
}
close(FH);


#----------------------------------------------------------------------
# Subroutines
#----------------------------------------------------------------------

#----------------------------------------------------------------------
# getPEHeader()
#----------------------------------------------------------------------
sub getPEHeader {
# Very simple check; if NT header is "PE", then valid PE file, and
# the e_lfanew value is returned (used throughout the rest of the
# code); else return undef;
	my $data = shift;
	my $e_lfanew = unpack("V",substr($data,0x3c,4));
	(unpack("V",substr($data,$e_lfanew,4)) == 0x4550) ? (return $e_lfanew) : (return undef);
}
#----------------------------------------------------------------------
# getImageFileHeader()
#----------------------------------------------------------------------
sub getImageFileHeader {
	my $data = shift;
	my $e_lfanew = shift;
	my %ifh;
	($ifh{machine},$ifh{number_sections},$ifh{datetimestamp},$ifh{ptr_symbol_table},
	$ifh{number_symbols},$ifh{size_opt_header},$ifh{characteristics}) 
		= unpack("vvVVVvv",substr($data,$e_lfanew + 4,20));
	return %ifh;
}
#----------------------------------------------------------------------
# getFileHeaderCharacteristics()
#----------------------------------------------------------------------
sub getFileHeaderCharacteristics {
	my $char = shift;
	my @list = ();
	my %chars = (0x0001 => "IMAGE_FILE_RELOCS_STRIPPED",
							 0x0002 => "IMAGE_FILE_EXECUTABLE_IMAGE",
							 0x0004 => "IMAGE_FILE_LINE_NUMS_STRIPPED",
							 0x0008 => "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
							 0x0010 => "IMAGE_FILE_AGGRESIVE_WS_TRIM",
							 0x0020 => "IMAGE_FILE_LARGE_ADDRESS_AWARE",
							 0x0080 => "IMAGE_FILE_BYTES_REVERSED_LO",
							 0x0100 => "IMAGE_FILE_32BIT_MACHINE",
							 0x0200 => "IMAGE_FILE_DEBUG_STRIPPED",
							 0x0400 => "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 
							 0x0800 => "IMAGE_FILE_NET_RUN_FROM_SWAP",
							 0x1000 => "IMAGE_FILE_SYSTEM",
							 0x2000 => "IMAGE_FILE_DLL",
							 0x4000 => "IMAGE_FILE_UP_SYSTEM_ONLY",	
							 0x8000 => "IMAGE_FILE_BYTES_REVERSED_HI");

	foreach my $c (keys %chars) {
		push(@list,$chars{$c}) if ($char & $c);
	}
	return @list;
}
#----------------------------------------------------------------------
# getFileHeaderMachine()
#----------------------------------------------------------------------

sub getFileHeaderMachine {
	my $word = shift;
	my %mach = (0x014c => "IMAGE_FILE_MACHINE_I386",
							0x014d => "IMAGE_FILE_MACHINE_I860",
							0x0184 => "IMAGE_FILE_MACHINE_ALPHA",
							0x01c0 => "IMAGE_FILE_MACHINE_ARM",
							0x01c2 => "IMAGE_FILE_MACHINE_THUMB",
							0x01f0 => "IMAGE_FILE_MACHINE_POWERPC",
							0x0284 => "IMAGE_FILE_MACHINE_ALPHA64",
	            0x0200 => "IMAGE_FILE_MACHINE_IA64",
	            0x8664 => "IMAGE_FILE_MACHINE_AMD64");
							 
	foreach my $m (keys %mach) {
		return $mach{$m} if ($word & $m);
	}
}
#----------------------------------------------------------------------
# getImageOptionalHeader()
#----------------------------------------------------------------------
sub getImageOptionalHeader {
	my $data = shift;
	my $e_lfanew = shift;
	my $size = shift;
	
	my $opt_hdr = unpack("v",substr($data, $e_lfanew + 24,2));
	
	my %opt32 = ();
	($opt32{magic},$opt32{majlinkver},$opt32{minlinkver},$opt32{codesize},
	$opt32{initdatasz},$opt32{uninitdatasz},$opt32{addr_entrypt},$opt32{codebase},
	$opt32{database},$opt32{imagebase},$opt32{sectalign},$opt32{filealign},
	$opt32{os_maj},$opt32{os_min},$opt32{image_maj},$opt32{image_min},
	$opt32{image_sz},$opt32{head_sz},$opt32{checksum},$opt32{subsystem},
	$opt32{dll_char},$opt32{rva_num}) 
		= unpack("vCCV9v4x8V3vvx20Vx4",substr($data,$e_lfanew + 24,$size));		
	return %opt32;
}
#----------------------------------------------------------------------
# getOptionalHeaderSubsystem()
#----------------------------------------------------------------------
sub getOptionalHeaderSubsystem {
	my $word = shift;
	my %subs = (0 => "IMAGE_SUBSYSTEM_UNKNOWN",
	            1 => "IMAGE_SUBSYSTEM_NATIVE",
	            3 => "IMAGE_SUBSYSTEM_WINDOWS_CUI",
	            2 => "IMAGE_SUBSYSTEM_WINDOWS_GUI",
	            5 => "IMAGE_SUBSYSTEM_OS2_CUI",
	            7 => "IMAGE_SUBSYSTEM_POSIX_CUI",
	            8 => "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
	            9 => "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
	            14 => "IMAGE_SUBSYSTEM_XBOX");

	foreach my $s (keys %subs) {
		return $subs{$s} if ($word == $s);
	}
}
#----------------------------------------------------------------------
# getDataDirectories()
#----------------------------------------------------------------------
sub getDataDirectories {
	my $data = shift;
	my $e_lfanew = shift;
	my $rva_num = shift;
	
	my %dd = ();
	my @dd_names = qw/ExportTable ImportTable ResourceTable ExceptionTable 
									 CertificateTable BaseRelocTable DebugTable ArchSpecific  
						 			GlobalPtrReg TLSTable LoadConfigTable BoundImportTable 
						 			IAT DelayImportDesc CLIHeader unused/;
	
	my @rva_list = unpack("VV" x $rva_num,substr($data,$e_lfanew + 24 + 96,8*$rva_num));	
	
	foreach my $i (0..($rva_num - 1)) {
		$dd{$dd_names[$i]}{rva} = $rva_list[($i*2)];
		$dd{$dd_names[$i]}{size} = $rva_list[($i*2)+1];
	}
	return %dd;
}

#----------------------------------------------------------------------
# getImageSectionHeaders()
#----------------------------------------------------------------------
sub getImageSectionHeaders {
	my $data = shift;
	my $num = shift;
# Each section is 40 bytes in size, and all sections are contiguous
	my $sec_sz = 40;
	my %sec    = ();
	foreach my $i (0..($num - 1)) {
		my ($name,$virt_sz,$virt_addr,$rdata_sz,$rdata_ptr,$char) 
			= unpack("a8V4x12V",substr($data,$i * $sec_sz,$sec_sz));
		$name =~ s/\00+$//;
		$sec{$name}{virt_sz}         = $virt_sz;
		$sec{$name}{virt_addr}       = $virt_addr;
		$sec{$name}{rdata_sz}        = $rdata_sz;
		$sec{$name}{rdata_ptr}       = $rdata_ptr;
		$sec{$name}{characteristics} = $char;
	} 
	return %sec;
}
#----------------------------------------------------------------------
# getResourceInfo()
#----------------------------------------------------------------------
sub getResourceInfo {
	my $offset = $_[0];
	my $data;
	my $rt_version = 0x10;
# Access the root directory of the ResourceTable to get the Types
	my %types = getResourceDir($offset);
	if (exists $types{$rt_version}) {
#		print "RT_VERSION dir pointer found.\n";
		
		my %nameid = getResourceDir($offset + ($types{$rt_version} - 0x80000000));
		my $i = scalar keys %nameid;
		my @k = keys %nameid;
		if ($i == 1) {
			my %langid = getResourceDir($offset + ($nameid{$k[0]} - 0x80000000));
			my $i = scalar keys %langid;
			my @k = keys %langid;
#			printf "\tLangID OFS -> 0x%x\n",$langid{$k[0]};
#			printf "\tOffset     -> 0x%x\n",$offset + $langid{$k[0]};
			seek(FH,$offset + $langid{$k[0]},0);
			read(FH,$data,8);
			my ($rva,$size) = unpack("V2",$data);
#			printf "RVA  -> 0x%x\n",$rva;
#			printf "Size -> 0x%x\n",$size;
			return $rva;
		}
		else {
			print "There are $i entries in the returned NameID hash.\n";
		}
	}
}
#----------------------------------------------------------------------
# getResourceDir()
#----------------------------------------------------------------------
sub getResourceDir {
# Takes an offset, reads the resource dir (16 bytes) to get the
# total number of entries; reads those entries and returns a hash
# of id/offset pairs
	my $offset = $_[0];
	seek(FH,$offset,0);
	read(FH,$data,16);
	my ($num_namedentries,$num_identries) = unpack("x12v2",$data);
#	print "Number of named entries = $num_namedentries\n";
#	print "Number of ID entries    = $num_identries\n";
	my $total = ($num_namedentries + $num_identries);
			
	my %dirs;
	my $v_ofs;
	foreach my $n (0..($total - 1)) {
		seek(FH,$offset + 16 + ($n * 8),0);
		read(FH,$data,8);
		my ($id,$ofs) = unpack("VV",$data);
		$dirs{$id} = $ofs;
	}
#	foreach my $k (keys %dirs) {
#		printf "0x%x -> 0x%x\n",$k,$dirs{$k};
#	}
	return %dirs;
}
#----------------------------------------------------------------------
# getVSVerInfo()
#----------------------------------------------------------------------
sub getVSVerInfo {
	my $offset = $_[0];
	my $data;
	seek(FH,$offset,0);
	read(FH,$data,6);
	my ($len,$val,$type) = unpack("v3",$data);
#	printf "\t -> 0x%x\n",$len;
#	printf "\t -> 0x%x\n",$val;
# VS_VERSIONINFO is 34 bytes in Unicode
	seek(FH,$offset + 0x06,0);
	read(FH,$data,0x22);
	$data =~ s/\00//g;
#	print "\t".$data."\n";
# Get the VS_FIXEDFILEINFO structure
	my %ffi = getFixedFileInfo($offset + 0x06 + 0x22);
#	printf "\tFixedFileInfo signature = 0x%x\n",$ffi{signature};
#	print "\n";
	my $str_finfo_ofs = $offset + 0x06 + 0x22 + 0x34;
	my %strinfo = getStringFileInfo($str_finfo_ofs);
	
	my $str_table_ofs = $str_finfo_ofs + 0x24;
	my %str_tbl = getStringTable($str_table_ofs);
#	printf "Length of the string table     = $str_tbl{len} -> 0x%x\n", $str_tbl{len};
# Now, parse the strings within the string table
	my %ver = undef;	
	my $tot_len = $str_tbl{read_len};
	my $str_ofs = $str_table_ofs + $str_tbl{read_len};
	while ($tot_len < $str_tbl{len}) {
		my %str = getString($str_ofs);
		$tot_len += $str{len};
		$str_ofs += $str{len};
		$ver{$str{szkey}} = $str{value};
	}
	return %ver;
}
#----------------------------------------------------------------------
# getFixedFileInfo()
#----------------------------------------------------------------------
sub getFixedFileInfo {
	my $offset = $_[0];
	my %ffi;
	my $data;
	seek(FH,$offset,0);
	read(FH,$data,13 * 4);
	($ffi{signature}, 
  $ffi{strucversion},
  $ffi{fileversionms},
  $ffi{fileversionls},
  $ffi{productversionms},
  $ffi{productversionls},
  $ffi{fileflagsmask},
  $ffi{fileflags},
  $ffi{fileos},
  $ffi{filetype},
  $ffi{filesubtype},
  $ffi{filedatems},
  $ffi{filedatels}) = unpack("V13",$data);
  return %ffi; 
}
#----------------------------------------------------------------------
# getStringFileInfo()
#----------------------------------------------------------------------
sub getStringFileInfo {
	my $offset = $_[0];
	my $data;
	my %str;
	seek(FH,$offset,0);
	read(FH,$data,6);
	($str{len}, $str{val}, $str{type}) = unpack("v3",$data);
	seek(FH,$offset + 6,0);
	read(FH,$data,0x1e);
	$data =~ s/\00//g;
	$str{szkey} = $data;
	$str{read_len} = 6 + 0x1e;
	return %str;
}
#----------------------------------------------------------------------
# getStringTable()
#----------------------------------------------------------------------
sub getStringTable {
	my $offset = $_[0];
	my $data;
	my %str;
	seek(FH,$offset,0);
	read(FH,$data,0x06);
	($str{len}, $str{val}, $str{type}) = unpack("v3",$data);
	seek(FH,$offset + 0x06,0);
	read(FH,$data,0x12);
	$data =~ s/\00//g;
	$str{szkey} = $data;
	$str{read_len} = 0x06 + 0x12;
	return %str;
}
#----------------------------------------------------------------------
# getString()
#----------------------------------------------------------------------
sub getString {
	my $ofs = $_[0];
	my $data;
	my %str;
	seek(FH,$ofs,0);
	read(FH,$data,0x06);
	($str{len}, $str{val_len}, $str{type}) = unpack("v3",$data);
	seek(FH,$ofs + 0x06,0);
	read(FH,$data,$str{len} - 6);
	my $marker = ($str{len} - 6) - ($str{val_len} * 2);
	$str{szkey} = substr($data,0,$marker);
	$str{szkey} =~ s/\00//g;
	$str{value} = substr($data,$marker,$str{len} - 6);
	$str{value} =~ s/\00//g;
	$str{len} += ($str{len} % 0x04);
	return %str;
}

#------------------------------------------
# _syntax()
# Print out help menu if command line arguments
# are used
#------------------------------------------
sub _syntax {
print<< "EOT";
OSID [-f filename] [-v] [-h]
OS ID - identify the Windows OS from a dump of physical memory 
Version 0.1_20061101

  -f filename....Name of dump file
  -v.............Verbose output                          
  -h.............Help (print this information)
  
Ex: C:\\>osid <filename>
    C:\\>osid -f <filename> -v
  
copyright 2006-2007 H. Carvey
EOT
}