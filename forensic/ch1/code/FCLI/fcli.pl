#! c:\perl\bin\perl.exe
# fcli.pl
# File Copy Client for FSP
use strict;
use Win32::GUI;
use Win32::FileOp qw(:DIALOGS);
use IO::Socket;
use Digest::MD5;
use Digest::SHA1;

#------------------------------------------------------------
# Globals
my %config;
my $main;
my $dialog;
my $tfServ;
my $tfPort;

#------------------------------------------------------------
# GUI
my $dataMenu = new Win32::GUI::Menu(   
    "&File" => "File",
    "   > &Open" => "FileOpen",
    "		> &Config" => "FileConfig",
    "   > -" => 0,
    "   > E&xit" => "FileExit",
    "&Help" => "Help",
    "   > &About" => "HelpAbout");

$main = Win32::GUI::Window->new(
									  -name => "Main",
									  -text => "FSP File Client",
										-width => 400, 
										-height => 400,
										-resize => 0,
										-menu   => $dataMenu,
										-maxsize => [400,400],
										-minsize => [400,400]); 

my $status = $main->AddStatusBar(-text => " ",
    									-width => $main->ScaleWidth);

# Add a listview to hold the list of filenames
my $lv = $main->AddListView(-name => "ListView",
														-text      => "",
    												-left      => 20,
    												-top       => 20,
    												-width     => 340,
    												-height    => 250,
    												-fullrowselect => 1,
    												-gridlines => 1,
   													-hottrack   => 1);

$main->ListView->InsertColumn(
    -index => 0,
    -width => $main->ListView->ScaleWidth,
    -text  => "File Name");
    
my $okbutton = $main->AddButton(-name => "OK",
															-text => "OK",
															-top  => 285,
															-left => 240,
															-width => 50,
															-height => 25);

my $cancelbutton = $main->AddButton(-name => "Cancel",
															-text => "Cancel",
															-top  => 285,
															-left => 310,
															-width => 50,
															-height => 25);    
    
#------------------------------------------------------------    
# Show
$main->Show();
#------------------------------------------------------------
# Event Loop
Win32::GUI::Dialog();
#------------------------------------------------------------
# Actions
sub Main_Terminate {exit 1;}

sub Main_Resize {
	$status->Move(0, $main->ScaleHeight-$status->Height);
  $status->Resize($main->ScaleWidth, $status->Height);
#  $status->Text("Window Resized.");
	$status->Update;
}

sub FileOpen_Click {
	my @files = OpenDialog(-title => "FRU:Select Files...",
	                            -filter => ['Filter 1' => '*.*'],
	                            -defaultfilter => 0,
	                            -handle => 0,
	                            -options => OFN_ALLOWMULTISELECT | OFN_LONGNAMES | OFN_EXPLORER 
	                                        | OFN_FILEMUSTEXIST| OFN_PATHMUSTEXIST);
	
	foreach my $file (@files) {
		$main->ListView->InsertItem(-text => $file);
	}
  0;
}

sub FileExit_Click { exit 1;}
sub Cancel_Click { exit 1;}

sub OK_Click {

	my $count = $main->ListView->Count();
	foreach my $item (0..$count-1) {
		my %node = $lv->GetItem($item);
		$status->Text("Getting ".$node{-text}." data");
		my %filedata = getFileData($node{-text});
		
		$status->Text("Sending ".$node{-text}." data");
		&sendFileData(%filedata);
		
		$status->Text("Copying ".$node{-text});
		&copyFile($node{-text});
	}
	&_sendCloseLog();
}

sub FileConfig_Click {
	my $w = 300;
	my $h = 200;
	$dialog = Win32::GUI::DialogBox->new(
									  -name => "Dialog",
									  -text => "Configuration Dialog",
										-width => $w, 
										-height => $h,
										-maxsize => [$w,$h],
										-minsize => [$w,$h]);
										
	my $label1 = $dialog->AddLabel(-text => " Server IP: ",
														  -top => 22,
														  -left => 20);	

	$tfServ = $dialog->AddTextfield(-name => "tfServ",
     													 -top  => 20,
     													 -left => 100,
     													 -text => "",
     													 -width => 150,
     													 -height => 22,
     													 -foreground => [0,0,0],
        											 -background => [255,255,255],
                               -tabstop  => 1);		
			
	my $label2 = $dialog->AddLabel(-text => " Server Port: ",
														  -top => 72,
														  -left => 20);	
	
	$tfPort = $dialog->AddTextfield(-name => "tfPort",
     													 -top  => 70,
     													 -left => 100,
     													 -text => "7070",
     													 -width => 75,
     													 -height => 22,
     													 -foreground => [0,0,0],
        											 -background => [255,255,255],
                               -tabstop  => 1);	
	
	my $button1 = $dialog->AddButton(-name => "DiagOK",
															-text => "OK",
															-top  => 120,
															-left => 130,
															-width => 50,
															-height => 25);

	my $button2 = $dialog->AddButton(-name => "DiagCancel",
															-text => "Cancel",
															-top  => 120,
															-left => 200,
															-width => 50,
															-height => 25);
	
	$dialog->Show();
}

sub HelpAbout_Click {
	my $msg = "File Copy Client for the FRU/FSP\n\n".
		        "FCli version 20061002\n\n".
	          "Author H. Carvey, keydet89\@yahoo\.com";
	Win32::GUI::MessageBox(0,$msg,"About",MB_ICONASTERISK);
}

sub DiagOK_Click {
	$config{server} = $tfServ->Text();
	$config{port} = $tfPort->Text();
	$status->Text("Server: ".$config{server}."   Port: ".$config{port});
	$dialog->Hide();
	$main->SetForegroundWindow();
}

sub DiagCancel_Click {
	$dialog->Hide();
	$main->SetForegroundWindow();
}

#-------------------------------------------------------------	
# send file contents
#-------------------------------------------------------------
sub copyFile {
	my $file = $_[0];
	my $line;
	my @list = (split(/\\/,$file));
	my $count = scalar @list;
	my $name = $list[$count-1];
	
	my $conn = new IO::Socket::INET (PeerAddr => $config{server},
                                 PeerPort => $config{port},
                                 Proto => 'tcp');
             
	if (! $conn) {
		my $msg = "There was an error creating the socket: $!";
		Win32::GUI::MessageBox(0,$msg,"Error creating socket",MB_ICONERROR);
		exit;
	}
	
	$conn->autoflush(1);
	$conn->send("FILE $name\n");
	if ($conn->recv($line, 256)) {
		if ($line =~ m/^OK$/i) {
			open(FH, $file) || die "Could not open $file: $!\n";
			binmode(FH);
			my $bin;
			my $len;
			my $written;
			my $offset;
			my $blksize = 2048;
			while ($len = sysread(FH,$bin,$blksize)) {
				die "System read error: $!\n" unless (defined $len);
				$offset = 0;
				while ($len) {
					$written = syswrite($conn,$bin,$len,$offset);
					die "System write error: $!\n" unless (defined $written);
					$offset += $written;
					$len -= $written;
				}
			}
			close(FH);
		}
	}
	close($conn);
}

#-------------------------------------------------------------	
# get file data
#-------------------------------------------------------------
sub getFileData {
	my $file = $_[0];
	my %props = ();
	my $line;
	my ($size,$atime,$mtime,$ctime) = (stat($file))[7..10];
	my ($md5,$sha1) = hash($file);
	$props{name} = $file;
	$props{size} = $size;
	$props{atime} = localtime($atime);
	$props{mtime} = localtime($mtime);
	$props{ctime} = localtime($ctime);
	$props{md5} = $md5;
	$props{sha1} = $sha1;
	return %props;
}

#-------------------------------------------------------------	
# send file data
# this same routine can be used to send any data
#-------------------------------------------------------------
sub sendFileData {
	my %filehash = @_;
	my $line;
# get filename from path
	my @list = (split(/\\/,$filehash{name}));
	my $count = scalar @list;
	my $name = (split(/\./,$list[$count-1]))[0];
	
	my $conn = new IO::Socket::INET (PeerAddr => $config{server},
                                 PeerPort => $config{port},
                                 Proto => 'tcp');
             
	die "Could not create socket: $!\n" unless $conn;
	$conn->autoflush(1); 	
	$conn->send("DATA $name\.dat\n");
	if ($conn->recv($line, 256)) {
		if ($line =~ m/^OK$/i) {
			foreach (keys %filehash) {
	  		$conn->send("$_:$filehash{$_}\n");
	  	}
#			print "Data sent.\n";
		}
	}	
	close($conn);
}

#------------------------------------------
# hash subroutine
# used by client, and by server to verify
#------------------------------------------
sub hash {
	my $file = $_[0];
	my $md5;
	my $sha;
	
	eval {
		open(FILE, $file);
  	binmode(FILE);
		$md5 = Digest::MD5->new->addfile(*FILE)->hexdigest;
		close(FILE);
	
		open(FILE, $file);
  	binmode(FILE);
		$sha = Digest::SHA1->new->addfile(*FILE)->hexdigest;
		close(FILE);
	};
	($@) ? (return $@) : (return ($md5,$sha));
}

#-------------------------------------------------------------	
# _sendCloseLog()
#-------------------------------------------------------------
sub _sendCloseLog {
	my $line;
	my $error;
	my $conn = new IO::Socket::INET (PeerAddr => $config{server},
                                   PeerPort => $config{port},
                                   Proto => 'tcp');
             
	if (!$conn) {
		$error = "Error setting up socket: $!";
		return 0;	
	}
	$conn->autoflush(1); 	
	$conn->send("CLOSELOG ".localtime(time));
	$status->Text("CLOSELOG command sent.");
	close($conn);
	return 1;
}