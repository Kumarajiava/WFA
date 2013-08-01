#! c:\perl\bin\perl.exe
#----------------------------------------------------------------------
# fvi.pl
# Uses Win32::File::VersionInfo to extract file version info from an 
# executable/PE file
#
# Usage: fvi.pl <filename>
# 
# Copyright 2006-2007 H. Carvey keydet89@yahoo.com
#----------------------------------------------------------------------
use strict;
use Win32::File::VersionInfo;

my $file = shift || die "You must enter a filename!\n";

if (-e $file) {
	my $ver = GetFileVersionInfo($file);
  if ($ver) {
  	print "Filename         : ".$file."\n";
		print "Type             : ".$ver->{Type}."\n";
		print "OS               : ".$ver->{OS}."\n";
		my @languages = keys %{$ver->{Lang}};
		my @lang = qw/FileDescription FileVersion InternalName CompanyName
		              Copyright Trademarks OriginalFilename ProductName
		              ProductVersion PrivateBuild SpecialBuild Comments/;
		print "Orig Filename    : ".$ver->{Lang}{$languages[0]}{OriginalFilename}."\n";
		print "File Descriptoin : ".$ver->{Lang}{$languages[0]}{FileDescription}."\n";              
		print "File Version     : ".$ver->{Lang}{$languages[0]}{FileVersion}."\n";
		print "Internal Name    : ".$ver->{Lang}{$languages[0]}{InternalName}."\n";
		print "Company Name     : ".$ver->{Lang}{$languages[0]}{CompanyName}."\n";
		print "Copyright        : ".$ver->{Lang}{$languages[0]}{LegalCopyright}."\n";
		print "Product Name     : ".$ver->{Lang}{$languages[0]}{ProductName}."\n";
		print "Product Version  : ".$ver->{Lang}{$languages[0]}{ProductVersion}."\n";
		print "Trademarks       : ".$ver->{Lang}{$languages[0]}{Trademarks}."\n";
	}
	else {
		my $err = Win32::FormatMessage Win32::GetLastError();
		print STDERR "Could not get version information: $err\n";
		exit 1;
	}
}
else {
	die "404 File not found.\n";
}
