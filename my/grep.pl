#!perl
use strict;
use Encode;
use Cwd;
use IO::File;
use File::Path;
use File::Grep qw(fgrep);
use File::Basename;


select( STDOUT ); 
$| = 1;
print "let's know the keywords list file\n";
my $pwgs = <STDIN>;
chomp($pwgs);
my $pwg = basename $pwgs;
my $doc = dirname $pwgs;
my $dir_name = $doc;
print "now,u are here:\t";
print $doc,"\n";
print "is this dir containing ur hashfiles? yes / ur dir\n";
my $pwgi =<STDIN>;
chomp($pwgi);
if ($pwgi=~m/yes$/){1;}
else{$doc = $pwgi;}
print $doc."\n";
chdir $doc;
my $dirsha =$doc;
$dirsha=~s/\/|\\/\#/g;
my @filelist;#存储读取到的所有文件列表

sub getfilelist {
    my $dir = $_[0];
    my @tmplist = ();
    $dir =~ s|/$|| if $dir =~ m|/$|;
    opendir DIR,"$dir" or die "$dir:$!";
    my @files = readdir DIR;
    foreach my $filename ( @files ){
        chomp $filename;

        if( $filename eq "." or $filename eq ".." or $filename =~ /^\./){
            next; #对以点"."开头的文件跳过
        }

        my $path = "$dir\\$filename";

        if(-f $path) {
            push(@tmplist,$path);
        }elsif(-l $path){
            next; #对于目录的软连接跳过
        }elsif(-d $path){
            push(@tmplist, getfilelist($path) );
        }else{
            print "what's this?: $path\n";
        }
    }
    closedir DIR;
    return @tmplist;
}
push(@filelist,getfilelist($doc));

foreach my $filepath (@filelist) {
	print $filepath,"\n";
}

my $WAAR = IO::File->new($pwgs,"r") or die $!;
my @line=<$WAAR>;
undef $WAAR;
my $fh;
my $pwgrep_out = $dir_name."\\".'pwgrepkumar_out.txt';
if (-e $pwgrep_out){
	$fh = IO::File->new( $pwgrep_out, q{>>} ) or die "Couldn't open $pwgrep_out:$!";
}else{
    $fh = IO::File->new( $pwgrep_out, q{>} ) or die "Couldn't open $pwgrep_out:$!";
}
$fh->autoflush(1);
foreach my $line (@line){
	chomp($line);
	my $keywords=$line;
	my $numm = 0;
	foreach my $filepath (@filelist) {
		my $filepatht = $filepath;
		next if $filepatht=~m/$pwg$/;
		if ( fgrep { /$keywords/ } $filepath) {
            $filepatht=~s/\\|\//\#/g;
            $filepatht=~s#$dirsha#\*#i;
            $filepatht=~s/\#/\\/g; 
			print STDOUT $keywords,"\t\t",$filepatht,"\n";
			print $fh $keywords,"\t\t",$filepatht,"\n";
			$numm++;
		}	
	}	
	print $fh "==".$numm;
}
undef $fh;