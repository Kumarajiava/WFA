#!c:\perl\bin\perl.exe
#-------------------------------------------------------
# Filename: toolchk.pl
# Script to collect information from IR/forensic tools 
# (ie, executables) for documentation purposes
#
#
# Author: H. Carvey, keydet89@yahoo.com
# copyright 2006-2007 H. Carvey
#-------------------------------------------------------
use strict;
use Win32::File::Ver;

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

my @temp1 = split(/\\/,$file);
my $name = (split(/\./,$temp1[scalar(@temp1) - 1]))[0];

open(FH,">",$name."\.dat") || die "Could not open file: $!\n";

print FH "URL/Location: \n";
print "\n";
# Get file size
my $size = (stat($file))[7];
print FH "Size  : ".$size." bytes \n";
print "\n";

# Compute file hash(es)

# Get file version information, if available
my $ver = GetFileVersion($file);
if ($ver) {
	print "Filename         : ".$file."\n";
	print "Type             : ".$ver->{Type}."\n";
	my @languages = keys %{$ver->{Lang}};
	my @lang = qw/FileDescription FileVersion InternalName CompanyName
	              Copyright Trademarks OriginalFilename ProductName
	              ProductVersion PrivateBuild SpecialBuild Comments/;
	print FH "Orig Filename    : ".$ver->{Lang}{$languages[0]}{OriginalFilename}."\n";
	print FH "File Descriptoin : ".$ver->{Lang}{$languages[0]}{FileDescription}."\n";              
	print FH "File Version     : ".$ver->{Lang}{$languages[0]}{FileVersion}."\n";
	print FH "Internal Name    : ".$ver->{Lang}{$languages[0]}{InternalName}."\n";
	print FH "Company Name     : ".$ver->{Lang}{$languages[0]}{CompanyName}."\n";
	print FH "Copyright        : ".$ver->{Lang}{$languages[0]}{Copyright}."\n";
	print FH "Product Name     : ".$ver->{Lang}{$languages[0]}{ProductName}."\n";
	print FH "Product Version  : ".$ver->{Lang}{$languages[0]}{ProductVersion}."\n";
	print FH "Trademarks       : ".$ver->{Lang}{$languages[0]}{Trademarks}."\n";
}
else {
	my $err = Win32::FormatMessage Win32::GetLastError();
	print FH "**Could not get version information: $err\n";
}

close(FH);