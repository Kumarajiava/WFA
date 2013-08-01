#! c:\perl\bin\perl.exe
#------------------------------------------
# FRUCJOB
# CLI helper for Forensics Server Project First Responder Utility
#
# 
#
# copyright 2007 H. Carvey keydet89@yahoo.com
#------------------------------------------
use strict;
use Win32::Job;

die "You must enter a command.\n" unless (@ARGV > 0);
#my ($exe,$arg) = split(/\s/,$cmd,2);

#my $cmd = join(' ',@ARGV);
#my ($exe,$arg) = split(/\s/,$cmd,2);

my $exe = $ARGV[0];
my $arg;
my $sz = scalar(@ARGV);
my @temp = ();
if ($sz > 1) {
	foreach (1..($sz - 1)) {
		push(@temp,$ARGV[$_]);
	}
	$arg = join(' ',@temp);
}

my @output;
my ($job,$ok);
eval {
	$job = Win32::Job->new;
  my $result = $job->spawn($exe,$exe." ".$arg);
  die "Value is undefined. ".$^E."\n" unless (defined $result);
  $ok = $job->run(60);
};
print $@."\n" if ($@);