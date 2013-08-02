#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# sam_parse.pl
# Perl script to retrieve user information from a raw Registry/SAM file
#
# Usage:
# C:\Perl>sam_parse.pl <path_to_SAM_file> [> sam_user.txt]
#
# This script is intended to be used against SAM files extracted from 
# from an image, either from the system32\config directory, or from system 
# restore points.
#
# copyright 2006-2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Parse::Win32Registry qw(:REG_);

# Included to permit compiling via Perl2Exe
#perl2exe_include "Parse/Win32Registry/Key.pm";
#perl2exe_include "Parse/Win32Registry/Value.pm";

my $sam = shift || die "You must enter a filename.\n";
die "$sam not found.\n" unless (-e $sam);

my %acb_flags = (0x0001 => "Account Disabled",
                 0x0002 => "Home directory required",
								 0x0004 => "Password not required",
 								 0x0008 => "Temporary duplicate account",
                 0x0010 => "Normal user account",
                 0x0020 => "MNS logon user account",
                 0x0040 => "Interdomain trust account",
                 0x0080 => "Workstation trust account",
                 0x0100 => "Server trust account",
                 0x0200 => "Password does not expire",
                 0x0400 => "Account auto locked");

my $reg = Parse::Win32Registry->new($sam);
my $root_key = $reg->get_root_key;

my %users = getUsers();
print "-" x 25,"\n";
print "User Information\n";
print "-" x 25,"\n";
foreach my $rid (keys %users) {
	($users{$rid}{fullname} eq "") ? (print $users{$rid}{name}."\n") :
		(print $users{$rid}{name}." (".$users{$rid}{fullname}.")\n");
	($users{$rid}{comment} eq "") ? () : (print $users{$rid}{comment}."\n");
	print "Key LastWrite Time = ".gmtime($users{$rid}{lastwrite})." (UTC)\n";
	my $ll;
	($users{$rid}{last_login} == 0)?($ll = "Never"):($ll = gmtime($users{$rid}{last_login})." (UTC)");
	print "Last Login         = ".$ll."\n";
	print "Login Count        = ".$users{$rid}{login_count}."\n";
	my $prd;
	($users{$rid}{pwd_reset_date} == 0)?($prd = "Never"):($prd = gmtime($users{$rid}{pwd_reset_date})." (UTC)");
	print "Pwd Reset Date     = ".$prd."\n";
	my $pfd;
	($users{$rid}{pwd_fail_date} == 0)?($pfd = "Never"):($pfd = gmtime($users{$rid}{pwd_fail_date})." (UTC)");
	print "Pwd Failure Date   = ".$pfd."\n";
	print "Account Flags: \n";
	foreach my $flag (keys %acb_flags) {
		print "  --> ".$acb_flags{$flag}."\n" if ($users{$rid}{flags} & $flag);
	}
	print "\n";
}

my %groups = getGroups();
print "-" x 25,"\n";
print "Group Information\n";
print "-" x 25,"\n";
foreach my $rid (keys %groups) {
	print $groups{$rid}{name}."\n";
	($groups{$rid}{comment} eq "") ? () : (print $groups{$rid}{comment}."\n");
	print "Key LastWrite Time = ".gmtime($groups{$rid}{lastwrite})." (UTC)\n";
	my @users = split(/,/,$groups{$rid}{users});
	if ($groups{$rid}{users} eq "None") {
		print "\tNo Users\n";
	}
	else {
		foreach my $u (@users) {
			if (exists $users{$u}) {
				print "\t".$users{$u}{name}."\n";
			}
			else {
				print "\t$u\n";
			}
		}
	}
	print "\n";
}

sub getUsers {
	my %users = ();
	my $user_path = 'SAM\\Domains\\Account\\Users';
	my $users = $root_key->get_subkey($user_path);

	my @user_list = $users->get_list_of_subkeys();
	if (@user_list) {
		foreach my $u (@user_list) {
			my $rid = $u->get_name();
			my $ts  = $u->get_timestamp();
			my $tag = "0000";
			if ($rid =~ m/^$tag/) {	
				my $v_value = $u->get_value("V");
				my $v = $v_value->get_data();
				my %v_val = parseV($v);
				$rid =~ s/^0000//;
				$rid = hex($rid);
				$users{$rid}{name} = $v_val{name};
				$users{$rid}{fullname} = $v_val{fullname};
				$users{$rid}{lastwrite} = $ts;
				$users{$rid}{comment} = $v_val{comment};
				my $f_value = $u->get_value("F");
				my $f = $f_value->get_data();
				my %f_val = parseF($f);
				$users{$rid}{last_login} = $f_val{last_login_date};
				$users{$rid}{pwd_reset_date} = $f_val{pwd_reset_date};
				$users{$rid}{pwd_fail_date} = $f_val{pwd_fail_date};
				$users{$rid}{flags} = $f_val{acb_flags};
				$users{$rid}{login_count} = $f_val{login_count}
			}
		}
	}
	else {
		undef %users;
	}
	return %users;
}

sub getGroups {
	my %sam_groups = ();
	my $grppath = 'SAM\\Domains\\Builtin\\Aliases';
	my $groups = $root_key->get_subkey($grppath);

	my %grps;
	foreach my $k ($groups->get_list_of_subkeys()) {
		if ($k->get_name() =~ m/^0000/) {
			$grps{$k->get_name()}{LastWrite} = $k->get_timestamp();
			$grps{$k->get_name()}{C_value} = $k->get_value("C")->get_data(); 
		}
	}
	foreach my $k (keys %grps) {
		my $name = $k;
		$name =~ s/^0000//;
		$sam_groups{$name}{lastwrite} = $grps{$k}{LastWrite};
		my %c_val = parseC($grps{$k}{C_value});
		$sam_groups{$name}{name} = $c_val{group_name};
		$sam_groups{$name}{comment} = $c_val{comment};
		$sam_groups{$name}{users} = $c_val{users};
	}
	return %sam_groups;
}


sub parseF {
	my $f = shift;
	my %f_value = ();
# last login date	
	$f_value{last_login_date} = _getTimeDate(unpack("VV",substr($f,8,8)));
#	password reset/acct creation
	$f_value{pwd_reset_date} = _getTimeDate(unpack("VV",substr($f,24,8)));
# Account expires
	$f_value{acct_exp_date} = _getTimeDate(unpack("VV",substr($f,32,8)));
# Incorrect password 	
	$f_value{pwd_fail_date} = _getTimeDate(unpack("VV",substr($f,40,8)));
	$f_value{rid} = unpack("V",substr($f,48,4));
	$f_value{acb_flags} = unpack("v",substr($f,56,2));
	$f_value{failed_count} = unpack("v",substr($f,64,2));
	$f_value{login_count} = unpack("v",substr($f,66,2));
	return %f_value;
}


sub parseV {
	my $v = shift;
	my %v_val = ();
	my $header = substr($v,0,44);
	my @vals = unpack("V*",$header);    
	$v_val{name}     = _uniToAscii(substr($v,($vals[3] + 0xCC),$vals[4]));
	$v_val{fullname} = _uniToAscii(substr($v,($vals[6] + 0xCC),$vals[7])) if ($vals[7] > 0);
	$v_val{comment}  = _uniToAscii(substr($v,($vals[9] + 0xCC),$vals[10])) if ($vals[10] > 0);
	return %v_val;
}

sub parseC {
	my $cv = $_[0];
	my %c_val = ();
	my $header = substr($cv,0,0x34);
	my @vals = unpack("V*",$header);
	
	$c_val{group_name} = _uniToAscii(substr($cv,(0x34 + $vals[4]),$vals[5]));
	$c_val{comment}    = _uniToAscii(substr($cv,(0x34 + $vals[7]),$vals[8]));
	
	my $num = $vals[12];
	my @users = ();
	my $ofs;
	$num -= 2 if ($c_val{group_name} eq "Users");			
	if ($num > 0) {
			my $count = 0;
			foreach my $c (1..$num) {
				$ofs = ($vals[10] + 52 + 25 + $count - 1);
				$ofs = ($vals[10] + 52 + 25 + $count - 1 + 24) if ($c_val{group_name} eq "Users");
				my $rid = unpack("v",substr($cv,$ofs,2));			
				push(@users,$rid);
				$count += (27 + 1) if ($count < $vals[11]);
			}
		}
		
		if ((scalar @users) > 0) {
			$c_val{users} = join(',',@users);
		}
		else {
			$c_val{users} = "None";
		}
	return %c_val;
}

#----------------------------------------------------------------
# _getTimeDate()
# Input : 2 DWORDs, each containing half of the LastWrite time
# Output: readable GMT time string
#----------------------------------------------------------------
sub _getTimeDate {
# Borrowed from Andreas Schuster's ptfinder code
	my $lo = shift;
	my $hi = shift;
	my $t;

	if ($lo == 0 && $hi == 0) {
		$t = 0;
	} else {
		$lo -= 0xd53e8000;
		$hi -= 0x019db1de;
		$t = int($hi*429.4967296 + $lo/1e7);
	};
	$t = 0 if ($t < 0);
	return $t;
}

sub _uniToAscii {
  my $str = $_[0];
  $str =~ s/\00//g;
  return $str;
} 