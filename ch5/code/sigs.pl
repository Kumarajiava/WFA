#! c:\perl\bin\perl.exe
#---------------------------------------------------------
# sigs.pl
# File signature analysis script for Windows systems
#
# Usage: C:\perl>[perl] sigs.pl [options]
#        Use '-h' for syntax
#
# Copyright 2004-2007 H. Carvey keydet89@yahoo.com
#---------------------------------------------------------
use strict;
use Getopt::Long;
my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(dir|d=s sub|s verbose|v file|f=s ini|i=s help|?|h));

if ($config{help} || ! %config) {
	\_syntax();
	exit 0;
}
$config{dir} = Win32::GetCwd() if (! $config{dir});
$config{ini} = 'headersig.txt' if (! $config{ini});

#-------------------------------------------------------------
# Read in the signature file
#-------------------------------------------------------------
my %sigs;
my $sig_file_read = 0;

if (-e $config{ini}) { 
	if (readsigfile($config{ini})) {
		print STDERR "Signature file successfully read.\n" if ($config{verbose});
		$sig_file_read = 1;
		foreach (keys %sigs) {
			my @list = @{$sigs{$_}};
		}
	}
	else {
		print "Signature file not read.\n";
	}
}
else {
	die "Could not locate signature file.\n";
}

print STDERR "Scan started: ".localtime(time)."\n" if ($config{verbose});

if (-d $config{dir}) {
	\dirSearch($config{dir});
}

print STDERR "Scan completed: ".localtime(time)."\n" if ($config{verbose});

#-------------------------------------------------------------
# dirSearch()
#-------------------------------------------------------------
sub dirSearch {
	my $dir = $_[0];
	my @dirs;
	my @files;
	if (-d $dir) {
		$dir = $dir."\\" unless ($dir =~ m/\\$/);
  	opendir(DIR,$dir) || die "Could not open $dir: $!\n";
  	@files = readdir(DIR);
  	close(DIR);
  
  	foreach my $file (@files) {
  		next if ($file eq '.' || $file eq '..');
  		$file = $dir.$file;
#  		print "File: $file\n" if (-f $file);
			\_checkFile($file) if (-f $file);
  		\dirSearch($file) if (-d $file && $config{sub});
  	}
	}
}

#-------------------------------------------------------------
# _checkFile()
#-------------------------------------------------------------
sub _checkFile {
	my $file = $_[0];
# Check file size; skip if 0	
	if ((stat($file))[7] == 0) {
		print STDERR "$file size is 0 bytes.\n" if ($config{verbose});
		next;
	}
	my $ext = getext($file); 
	my ($hex,$resp) = getsig($file);
	if (0 == $resp) {
		print STDERR "Could not open $file: $!\n";
		next;
	}
	if ($sig_file_read) {
		my $match = 0;
		foreach my $key (keys %sigs) {
			if ($hex =~ m/^$key/) {
				$match = 1;
				if (grep(/$ext/i,@{$sigs{$key}})) {
					print "$file, Sig match.\n";
				}
				else {
					$hex = substr($hex,0,10);
					print "$file, Sig does not match. ($ext,$hex)\n";
				}
			}
		}
		$hex = substr($hex,0,10);
		print "$file, Sig not listed. ($ext,$hex)\n" if (!$match);
	}
}

#-------------------------------------------------------------
# getext()
#-------------------------------------------------------------
sub getext {
	my $file = $_[0];
	my $ext;
	my @filelist = split(/\./,$file);
	(@filelist > 1) ? ($ext = $filelist[@filelist - 1]) :
		($ext = "none");
	return $ext;
}

#-------------------------------------------------------------
# getsig()
#-------------------------------------------------------------
sub getsig {
	my $file = $_[0];
	my $success = 0;
	my $hex;
	eval {
		if (open(FH, $file)) {
			binmode(FH);
			my $bin;
			sysread(FH,$bin,20);
			close(FH);
			$hex = uc(unpack("H*",$bin));
			$success = 1;
		}
	};
	return ($hex,$success);
}

#-------------------------------------------------------------
# readsigfile()
#-------------------------------------------------------------
sub readsigfile {
	my $file = $_[0];
	if (-e $file) { 
		open(FH,$file) || die "Could not open $file: $!\n";
		while(<FH>) {
# skip lines that begin w/ # or are blank
			next if ($_ =~ m/^#/ || $_ =~ m/^\s+$/);
			chomp;
			my ($sig,$tag) = (split(/,/,$_,3))[0,1];
			my @list = split(/;/,$tag);
			foreach (@list) {
				$_ =~ s/\s//;
				$_ =~ s/\.//;
			}
# %sigs is a global variable
			$sigs{$sig} = [@list];
		}
		close(FH);
		return 1;
	}
	else {
		return undef;
	}
}

sub _syntax {
	print<< "EOT";
Sigs v1.0 [-d dir] [-s] [-v] [-f filename] [-i filename] [-h]
Check file signatures
Output sent to console in .csv format
  -d dir..........Directory to scan
  -s sub..........Enumerate through subdirectories
  -v..............Verbose output (verbose output goes to STDERR)
  -f filename.....Name of file to check
  -i filename.....Name of signature file to use
                  (default=headersig.txt)
  -h..............Help (print this information)
		
copyright 2004-2007 H. Carvey
EOT
}