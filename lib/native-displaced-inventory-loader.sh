#!/usr/bin/env bash
# Transport-neutral, release-pinned native inventory loader template.
# The private integration replaces the single payload marker with the exact
# base64 release artifact before streaming this template to a target host.
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH NPM_CONFIG_PREFIX PYTHONPATH PYTHONHOME
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
set -euo pipefail

fail(){ printf 'native-displaced-inventory-loader: %s\n' "$1" >&2;exit 20; }
STAT=/usr/bin/stat
OPENSSL=/usr/bin/openssl
PERL=/usr/bin/perl
[[ -f "$STAT"&&! -L "$STAT"&&-x "$STAT"&&-f "$OPENSSL"&&! -L "$OPENSSL"&&-x "$OPENSSL"&&-f "$PERL"&&! -L "$PERL"&&-x "$PERL" ]]||fail 'trusted base tools unavailable'
meta(){ "$STAT" -c '%u:%g:%a:%d:%i:%s' "$1" 2>/dev/null||"$STAT" -f '%u:%g:%Lp:%d:%i:%z' "$1" 2>/dev/null; }
trusted_file(){
  local path="$1" value uid gid mode parent
  [[ "$path" == /*&&-f "$path"&&! -L "$path"&&-x "$path" ]]||return 1
  value="$(meta "$path")"||return 1;IFS=: read -r uid gid mode _ <<<"$value"
  [[ "$uid" == 0&&"$gid" == 0&&"$mode" =~ ^[0-7]{3,4}$ ]]||return 1
  (( (8#$mode & 022)==0 ))||return 1
  parent="${path%/*}";[[ -n "$parent" ]]||parent=/
  while :;do
    [[ -d "$parent"&&! -L "$parent" ]]||return 1
    value="$(meta "$parent")"||return 1;IFS=: read -r uid gid mode _ <<<"$value"
    [[ "$uid" == 0&&"$gid" == 0&&"$mode" =~ ^[0-7]{3,4}$ ]]&&(( (8#$mode & 022)==0 ))||return 1
    [[ "$parent" == / ]]&&break;parent="${parent%/*}";[[ -n "$parent" ]]||parent=/
  done
}
sha(){
  local value
  value="$(LC_ALL=C "$OPENSSL" dgst -sha256 -r "$1" 2>/dev/null)"||fail 'SHA-256 failed'
  value="${value%% *}";[[ "$value" =~ ^[a-f0-9]{64}$ ]]||fail 'malformed SHA-256';printf %s "$value"
}

target_root="${1:-}";capture_nonce="${2:-}";native_sha="${3:-}";native_bytes="${4:-}";capture_mode="${5:-inventory}";selected_rel_hex="${6:-}"
[[ "$target_root" == /*&&"$target_root" != /&&${#target_root} -le 4096&&"$target_root" != */&&"$target_root" != *//* ]]||fail 'invalid bounded target'
[[ "$capture_nonce" =~ ^[a-f0-9]{64}$&&"$native_sha" =~ ^[a-f0-9]{64}$&&"$native_bytes" =~ ^[0-9]+$&&"$native_bytes" -ge 1&&"$native_bytes" -le 1048576 ]]||fail 'invalid release binding'
[[ ( "$capture_mode" == inventory||"$capture_mode" == diagnostic )&&-z "$selected_rel_hex"||"$capture_mode" == rollback&&"$selected_rel_hex" =~ ^[a-f0-9]{2,8192}$&&$((${#selected_rel_hex}%2)) -eq 0||"$capture_mode" == volatile-inventory&&${#selected_rel_hex} -le 32768&&"$selected_rel_hex" =~ ^[ACL]:[a-f0-9]+(,[ACL]:[a-f0-9]+)*$ ]]||fail 'invalid bounded capture mode'
trusted_file "$STAT"&&trusted_file "$OPENSSL"&&trusted_file "$PERL"||fail 'base tool trust failed'

perl_identity="$(meta "$PERL")";perl_sha="$(sha "$PERL")"
runtime_identity="loader=/usr/bin/perl|loader_sha=$perl_sha|loader_meta=$perl_identity|helper_sha=$native_sha|transport=sealed_memfd_execveat_v1"
printf 'NATIVE_BOOTSTRAP_START_V1\t%s\t%s\t%s\n' "$capture_nonce" "$perl_sha" "$native_sha" >&2
"$PERL" -T -e '
use strict;use warnings;use Fcntl qw(F_GETFD F_SETFD FD_CLOEXEC SEEK_SET);
sub valid_root {
  my($p)=@_;return 0 unless defined($p)&&$p=~m{\A/}&&$p ne "/"&&length($p)<=4096&&$p!~m{//}&&$p!~m{/\z};
  my @parts=split(m{/},substr($p,1),-1);return 0 unless @parts&&@parts<=64;
  for(@parts){return 0 if $_ eq ""||$_ eq "."||$_ eq ".."||index($_,"\0")>=0;}return 1;
}
my($expected,$expected_bytes,$root,$nonce,$identity,$mode,$selected)=@ARGV;
my($clean_expected)=$expected=~/\A([a-f0-9]{64})\z/;my($clean_bytes)=$expected_bytes=~/\A([0-9]{1,7})\z/;my($clean_nonce)=$nonce=~/\A([a-f0-9]{64})\z/;my($clean_mode)=$mode=~/\A(inventory|rollback|diagnostic|volatile-inventory)\z/;
my @root_parts=valid_root($root)?split(m{/},substr($root,1),-1):();my @clean_parts;for my $part(@root_parts){my($clean)=$part=~/\A([^\0\/]+)\z/;die "loader: invalid invocation\n" unless defined($clean)&&$clean ne "."&&$clean ne "..";push @clean_parts,$clean;}my $clean_root=@clean_parts?"/".join("/",@clean_parts):undef;
my $helper_in_identity=defined($clean_expected)?$clean_expected:"";my($clean_identity)=$identity=~/\A(loader=\/usr\/bin\/perl\|loader_sha=[a-f0-9]{64}\|loader_meta=[0-9]+:[0-9]+:[0-7]{3,4}:[0-9]+:[0-9]+:[0-9]+\|helper_sha=\Q$helper_in_identity\E\|transport=sealed_memfd_execveat_v1)\z/;
my $clean_selected="";if(defined($clean_mode)&&$clean_mode eq "rollback"){($clean_selected)=$selected=~/\A((?:[a-f0-9]{2}){1,4096})\z/;}elsif(defined($clean_mode)&&$clean_mode eq "volatile-inventory"&&length($selected)<=32768){($clean_selected)=$selected=~/\A((?:[ACL]:(?:[a-f0-9]{2}){1,4096})(?:,[ACL]:(?:[a-f0-9]{2}){1,4096}){0,63})\z/;}
die "loader: invalid invocation\n" unless defined($clean_expected)&&defined($clean_bytes)&&$clean_bytes>=1&&$clean_bytes<=1048576&&defined($clean_root)&&defined($clean_nonce)&&defined($clean_identity)&&defined($clean_mode)&&((($clean_mode eq "inventory"||$clean_mode eq "diagnostic")&&$selected eq "")||(($clean_mode eq "rollback"||$clean_mode eq "volatile-inventory")&&defined($clean_selected)&&length($clean_selected)));
($expected,$expected_bytes,$root,$nonce,$identity,$mode,$selected)=($clean_expected,$clean_bytes,$clean_root,$clean_nonce,$clean_identity,$clean_mode,$clean_selected);
local $/;my $text=<STDIN>;defined($text) or die "loader: payload unavailable\n";die "loader: encoded payload cap\n" if length($text)>1500000;$text=~s/\s+//g;die "loader: base64 framing\n" unless length($text) && length($text)%4==0 && $text=~/\A[A-Za-z0-9+\/]*={0,2}\z/;
my %v;@v{("A".."Z","a".."z",0..9,"+","/")}=(0..63);my $raw="";
for(my $i=0;$i<length($text);$i+=4){my @c=map substr($text,$i+$_,1),0..3;my @n=map {$_ eq "="?0:$v{$_}} @c;die "loader: base64 alphabet\n" if grep {!defined} @n;my $x=($n[0]<<18)|($n[1]<<12)|($n[2]<<6)|$n[3];$raw.=chr(($x>>16)&255);$raw.=chr(($x>>8)&255) if $c[2] ne "=";$raw.=chr($x&255) if $c[3] ne "=";}die "loader: decoded payload size\n" unless length($raw)==$expected_bytes;
my $memfd_name="wapp-native-displaced-inventory";my $fd=syscall(319,$memfd_name,2);die "loader: memfd_create unavailable\n" if $fd<0;
open(my $fh,"+<&",$fd) or die "loader: memfd handle\n";binmode($fh);my $off=0;while($off<length($raw)){my $n=syswrite($fh,$raw,length($raw)-$off,$off);die "loader: memfd write\n" unless defined($n)&&$n>0;$off+=$n;}die "loader: memfd size\n" unless $off==length($raw);
die "loader: memfd seal\n" unless fcntl($fh,1033,15);my $seals=fcntl($fh,1034,0);die "loader: incomplete memfd seals\n" unless defined($seals)&&($seals&15)==15;
my @args=("wapp-native-displaced-inventory",$mode,$root,$nonce,$expected,$identity,"$fd");push @args,$selected if $mode eq "rollback"||$mode eq "volatile-inventory";my @hold=map "$_\0",@args;my $ptr="";$ptr.=pack("p",$_) for @hold;$ptr.=pack("J",0);my $env=pack("J",0);
my $empty_path="";syscall(322,$fd,$empty_path,$ptr,$env,0x1000);die "loader: execveat unavailable\n";
' "$native_sha" "$native_bytes" "$target_root" "$capture_nonce" "$runtime_identity" "$capture_mode" "$selected_rel_hex" <<'WAPP_NATIVE_HELPER_BASE64_V1'
__WAPP_NATIVE_HELPER_BASE64_PAYLOAD__
WAPP_NATIVE_HELPER_BASE64_V1
[[ "$(meta "$PERL")" == "$perl_identity"&&"$(sha "$PERL")" == "$perl_sha" ]]||fail 'memfd loader drift during capture'
exit 0
