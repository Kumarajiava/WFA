#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------
# lspi.pl - parse process image from a Windows 2000 phys. memory/RAM dump,
#           (LiSt Process Image)
#  
# Version 0.4
#
# Usage: lspi.pl <filename> <offset>
#        Determine the offset of the the process you're interested in by 
#        running lsproc.pl first
#
# Changelog:
# 20060721 - created
#
# copyright 2007 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------------
use strict;
print "lspi - list Windows 2000 process image (v.0.4 - 20060721)\n";
print "Ex: lspi <path_to_dump_file> <offset_from_lsproc>\n";
print "\n";
my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);
my $offset = hex(shift) || die "You must enter a process offset.\n";
my $data;
my $error;
my ($size,$type);

#-----------------------------------------------------------------
# Global Variables
#-----------------------------------------------------------------
my $pagecount  = 0;
my %imagepages = ();
my @pagedout   = ();
my $outfile;

open(FH,"<",$file) || die "Could not open $file : $!\n";
binmode(FH);
seek(FH,$offset,0);
read(FH,$data,4);
my ($type,$size) = unpack("CxCx",$data);
if ($size == 0x1b && $type == 0x03) {	
	seek(FH,$offset,0);
	my $bytes = read(FH,$data,0x290);
	if (0x290 == $bytes) {
		if (my %proc = isProcess($data)) {
			print "Process Name : ".$proc{name}."\n";
			$outfile = $proc{name}."\.img";
			print "PID          : ".$proc{pid}."\n";
			my $dtb = $proc{directorytablebase};
			printf "DTB          : 0x%08x\n",$dtb;
			my $peb_ofs = getOffset($proc{peb},$dtb);
			die "The page located at the address for the PEB has been paged out.\n" if ($peb_ofs == 0);
			printf "PEB          : 0x%08x (0x%08x)\n",$proc{peb},$peb_ofs;
			
# Get specific info from the PEB				
			if ($peb_ofs != 0x0) {
				my %peb_data = getPEBData($peb_ofs,$dtb);
				
				my $imgbaseofs = getOffset($peb_data{img_base_addr},$dtb);
				die "The page located at the ImageBaseAddress for this process has been paged out.\n" if ($imgbaseofs == 0);
				printf "ImgBaseAddr  : 0x%08x (0x%08x)\n",$peb_data{img_base_addr},$imgbaseofs;
				print "\n";
				if ($imgbaseofs != 0x00 && getImgBase($imgbaseofs)) {
# We're now ready to begin processing
					$pagecount++;
					$imagepages{$pagecount} = $imgbaseofs;
# Read in the first 4K page located at the ImageBaseAddress offset					
					seek(FH,$imgbaseofs,0);
					read(FH,$data,0x1000);
# Check the NT Header					
					my $e_lfanew = unpack("V",substr($data,0x3c,4));
					printf "e_lfanew = 0x%x\n",$e_lfanew; 
					
					my $nt = unpack("V",substr($data,$e_lfanew,4));
					die "Not an NT header.\n" if ($nt != 0x4550);
					printf "NT Header = 0x%x\n",$nt;
					
					print "\n";
					print "Reading the Image File Header\n";
					my %ifh;
					($ifh{machine},$ifh{number_sections},$ifh{datetimestamp},$ifh{ptr_symbol_table},
						$ifh{number_symbols},$ifh{size_opt_header},$ifh{characteristics}) 
						= unpack("vvVVVvv",substr($data,$e_lfanew + 4,20));
					print  "Sections = $ifh{number_sections}\n";
					printf "Opt Header Size  = 0x%08x (".$ifh{size_opt_header}." bytes)\n",$ifh{size_opt_header};
					print "Characteristics: \n";
# Translate the image file header characteristics
					my @char = getFileHeaderCharacteristics($ifh{characteristics});
					foreach (@char) {print "\t$_\n";}
					print "\n";
					print "Machine = ".getFileHeaderMachine($ifh{machine})."\n";
					print "\n";
					
					print "Reading the Image Optional Header\n";
					print "\n";
					my $opt_hdr = unpack("v",substr($data, $e_lfanew + 24,2));
					printf "Opt Header Magic = 0x%x\n",$opt_hdr;
	
					my %opt32 = ();
					($opt32{magic},$opt32{majlinkver},$opt32{minlinkver},$opt32{codesize},
		 				$opt32{initdatasz},$opt32{uninitdatasz},$opt32{addr_entrypt},$opt32{codebase},
		 				$opt32{database},$opt32{imagebase},$opt32{sectalign},$opt32{filealign},
		 				$opt32{os_maj},$opt32{os_min},$opt32{image_maj},$opt32{image_min},
		 				$opt32{image_sz},$opt32{head_sz},$opt32{checksum},$opt32{subsystem},
		 				$opt32{dll_char},$opt32{rva_num}) = unpack("vCCV9v4x8V3vvx20Vx4",substr($data,$e_lfanew + 24,$ifh{size_opt_header}));		
					print  "Subsystem     : ".getOptionalHeaderSubsystem($opt32{subsystem})."\n";
					printf "Entry Pt Addr : 0x%08x\n",$opt32{addr_entrypt};
					printf "Image Base    : 0x%08x\n",$opt32{imagebase};
					printf "File Align    : 0x%08x\n",$opt32{filealign};
					
# get Data Directories
  				print "\n";
					print "Reading the Image Data Directory information\n";
					my %dd = ();
					my @dd_names = qw/ExportTable ImportTable ResourceTable ExceptionTable 
						 CertificateTable BaseRelocTable DebugTable ArchSpecific  
						 GlobalPtrReg TLSTable LoadConfigTable BoundImportTable 
						 IAT DelayImportDesc CLIHeader unused/;
	
					my @rva_list = unpack("VV" x $opt32{rva_num},substr($data,$e_lfanew + 24 + 96,8*$opt32{rva_num}));	
	
					foreach my $i (0..($opt32{rva_num} - 1)) {
						$dd{$dd_names[$i]}{rva} = $rva_list[($i*2)];
						$dd{$dd_names[$i]}{size} = $rva_list[($i*2)+1];
					}
					print "\n";
					printf "%-20s %-10s %-10s\n","Data Directory","RVA","Size";
					printf "%-20s %-10s %-10s\n","-" x 14,"-" x 3, "-" x 4;
					foreach my $name (keys %dd) {
						printf "%-20s 0x%08x 0x%08x\n",$name,$dd{$name}{rva},$dd{$name}{size};
					}
	
# Read section headers
  				print "\n";
  				print "Reading Image Section Header information\n";
  				print "\n";
					my $num  = $ifh{number_sections};
					my $size = 40;
					my $ofs  = $e_lfanew + 24 + 96 + 8*$opt32{rva_num};
					my $sect = substr($data,$ofs,$num * $size);
					my %sections = getImageSectionHeaders($sect,$num);
	
					printf "%-8s %-10s  %-10s  %-10s  %-10s  %-10s\n","Name","Virt Sz","Virt Addr","rData Ofs","rData Sz","Char";
					printf "%-8s %-10s  %-10s  %-10s  %-10s  %-10s\n","-" x 4,"-" x 7,"-" x 9,"-" x 9,"-" x 8,"-" x 4;
	
					my %sec_order = ();
	
					foreach my $sec (keys %sections) {
						printf "%-8s 0x%08x  0x%08x  0x%08x  0x%08x  0x%08x\n",$sec,$sections{$sec}{virt_sz},
						$sections{$sec}{virt_addr},$sections{$sec}{rdata_ptr},$sections{$sec}{rdata_sz},
						$sections{$sec}{characteristics};
						$sec_order{$sections{$sec}{virt_addr}} = $sec;
					}
					print "\n";
# Now that we have information from the section headers, we need calculate the offsets of the pages
# within the dump file, and check to see if any of the pages have been paged out.					
					foreach my $order (sort {$a <=> $b} keys %sec_order) {
						my $sec = $sec_order{$order};
						my $num_pages = $sections{$sec}{rdata_sz} / 0x1000;
						foreach my $n (0..($num_pages - 1)) {
							my $page = $peb_data{img_base_addr} + $sections{$sec}{virt_addr} + (0x1000 * $n);
							my $offset = getOffset($page, $dtb);
							if ($offset == 0) {
								push(@pagedout,$page);
							}
							else {
								$pagecount++;
								$imagepages{$pagecount} = $offset;
							}
#							seek(FH,$offset,0);
#							read(FH,$data,0x1000);
#							syswrite(OUT,$data,length($data));			
						}
					}
					if (scalar(@pagedout) > 0) {
						print "There are ".scalar(@pagedout)." pages paged out of physical memory.\n";
						map{printf "\t0x%08x\n",$_}(@pagedout);
						print "If any pages are paged out, the image file cannot be completely reassembled.\n";
					}
					else {
						print "Reassembling image file into $outfile\n";
						open(OUT,">",$outfile) || die "Could not open $outfile: $!\n";
						binmode(OUT);
						my $size = 0; 
						foreach my $i (sort {$a <=> $b} keys %imagepages) {
							seek(FH,$imagepages{$i},0);
							read(FH,$data,0x1000);
							syswrite(OUT,$data,length($data));
							$size += length($data);
						}
						close(OUT);
						print "Bytes written = $size\n";
						print "New file size = ".(stat($outfile))[7]."\n";
					} 
				}
			}				
		}
	}
}

close(FH);

#---------------------------------------------------------
# isProcess()
# check to see if we have a valid process (Win2K SP4)
# Input : 652 bytes starting at the offset
# Output: Hash containing EPROCESS block info, undef if not a valid 
#         EPROCESS block
#---------------------------------------------------------
sub isProcess {
	my $data = shift;
	my %proc = ();
	my $event1 = unpack("V",substr($data,0x13c,4));
	my $event2 = unpack("V",substr($data,0x164,4));
	
	if ($event1 == 0x40001 && $event2 == 0x40001) {
# Use this area to populate the EPROCESS structure		
		my $name = substr($data,0x1fc,16);
		$name =~ s/\00//g;
		$proc{name} = $name;
#		$proc{exitstatus} = unpack("V", substr($data,0x06c,4));
# Get Active Process Links for EPROCESS block
#		($proc{flink},$proc{blink})  = unpack("VV",substr($data,0x0a0,8));
		
		$proc{pid} = unpack("V",substr($data,0x09c,4));
#	  $proc{ppid}	= unpack("V",substr($data,0x1c8,4));
#	  ($proc{subsysmin},$proc{subsysmaj}) = unpack("CC",substr($data,0x212,2));
		$proc{directorytablebase} = unpack("V",substr($data,0x018,4));
	  $proc{peb} = unpack("V",substr($data,0x1b0,4));
	  $proc{exitprocesscalled} = unpack("C",substr($data,0x1aa,1));
#	  $proc{pimagefilename} = unpack("V",substr($data,0x284,4));
	}
	else {
# Not an EPROCESS block
	}
	return %proc;
}

#---------------------------------------------------------
# getOffset()
# Get physical offset within dump, based on logical addresses
# Translates a logical address to a physical offset w/in the dump
#   file
# Input : two addresses (ex: PEB and DirectoryTableBase)
# Output: offset within file
#---------------------------------------------------------
sub getOffset {
	my $peb = shift;
	my $dtb = shift;
	my $record;
	my $pdi = $peb >> 22 & 0x3ff;
	my $pda = $dtb + ($pdi * 4);
	seek(FH,$pda,0);
	read(FH,$record,4);	
	my $pde = unpack("V",$record);
# Determine page size if needed
# $pde & 0x080; if 1, page is 4Mb; else, 4Kb
# Check to see if page is present
	if ($pde & 0x1) {
		my $pti = $peb >> 12 & 0x3ff;
		my $ptb = $pde >> 12;
		seek(FH,($ptb * 0x1000) + ($pti * 4),0);
		read(FH,$record,4);	
		my $pte = unpack("V",$record);
		if ($pte & 0x1) {
			my $pg_ofs = $peb & 0x0fff;
			return ((($pte >> 12) * 0x1000) + $pg_ofs);	
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
}

#---------------------------------------------------------
# getPEBData()
# Input : physical offset to PEB
# Output: data from PEB (Note: Virtual addresses are not 
#         translated to physical offsets in this subroutine)
#---------------------------------------------------------
sub getPEBData() {
	my $ofs = shift;
	my $dtb = shift;
	my %peb = ();
	seek(FH,$ofs,0);
	my $record;
	read(FH,$record,20);
	($peb{inheritedaddrspace},$peb{readimgfileexecopts},$peb{beingdebugged},$peb{mutant},
		$peb{img_base_addr},$peb{peb_ldr},$peb{params}) = unpack("C3xV4",$record);
	return %peb;
}

#---------------------------------------------------------
# getImgBase()
# Read 4K at image base offset (from PEB)
# Input : Physical offset to the image base addr
# Output: dump of memory
#---------------------------------------------------------
sub getImgBase {
	my $ofs = shift;
	my $data;
	seek(FH,$ofs,0);
	read(FH,$data,2);
	my $mz = unpack("v",$data);
	if ($mz == 0x00005a4d) {
		return 1;
	}
	else {
		return 0;
	}
}

#----------------------------------------------------------------

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
