#!perl


use strict;
use Cwd;
use File::Spec;
use File::Basename;
use Digest::MD5;
use File::Copy qw(cp);
use File::Remove;

my $cwd0 = getcwd;
my @files = <*>;
my $file;
my $ext = "MD5";
my $myself ="md5summerjxl\.exe";
my $md5=$cwd0."\\".$ext;
my $FFILE = IO::File->new($ext,q{>} ) or die "Couldn't open $ext:$!";
foreach $file(@files)
{
	my $path = File::Spec->catfile( $cwd0, $file );
	&filelist($path);
}
$FFILE->close;

if (-e $md5) {
	open(FHH, $md5) or die "Can't open '$md5': $!";
    binmode(FHH);
    my $cpfile = Digest::MD5->new->addfile(*FHH)->hexdigest;        
    close (FHH);
	cp($ext,$cpfile."\.txt");	
}
File::Remove::remove $ext;
if ( pid == fork()) {
	exit;
}else{
	system(del ,$0);
	exit;
}

sub filelist
{
	my $path = shift @_;
	my $file_name = basename $path;
	if(-d $file_name)#如果是文件夹，进入并遍历
	{		
		chdir $path or die "can't chdir $path:$!";
		my $cwd = getcwd;
		my @files = <*>;
		my $file;
		my $count = 0;
		foreach $file(@files)
		{
			$count++;
			my $path = File::Spec->catfile( $cwd, $file );
			&filelist($path);
		}
		if ($count eq @files)#当前文件夹已经遍历完，回到上一级文件夹
		{
			my $dir_name = dirname $path; 
			chdir "$dir_name\.." or die "can't chdir $dir_name\..:$!";
		}
	}
	else
	{
		open(FH, $path) or die "Can't open '$path': $!";
        binmode(FH);
        my $hash=Digest::MD5->new->addfile(*FH)->hexdigest;        
        close (FH);
        my $cwd1=$cwd0;
        $cwd1=~s/\//\#/g;
        $path=~s/\\/\#/g;
        $path=~s#$cwd1#\.#g;
        $path=~s/\#/\\/g;        
        next if $path eq "\.\\$myself";
		print $FFILE "<======$hash======>";
        print $FFILE "$path\n";
	}
}