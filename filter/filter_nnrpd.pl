#
# Do any initialization steps.
#
use Digest::MD5  qw(md5_base64);
use Digest::SHA1();
use Digest::HMAC_SHA1();
use MIME::Base64();

$CANCEL_LOCK = 'secretword';

#
# Filter
#
sub filter_post {
   my $rval = "" ;             # assume we'll accept.
   $modify_headers = 1;

   # Cancel-Lock / Cancel-Key
   add_cancel_lock(\%hdr, $user);
     
   if (exists( $hdr{"Control"} ) && $hdr{"Control"} =~ m/^cancel\s+(<[^>]+>)/i) {
      my $key = calc_cancel_key($user, $1);
      add_cancel_item(\%hdr, 'Cancel-Key', $key);
   }
   elsif (exists( $hdr{"Supersedes"} )) {
      my $key = calc_cancel_key($user, $hdr{"Supersedes"});
      add_cancel_item(\%hdr, 'Cancel-Key', $key);
   }
     
   return $rval;
}

#
# Cancel-Lock / Cancel-Key
#
sub add_cancel_item($$$) {
   my ( $r_hdr, $name, $value ) = @_;
   my $prefix = $r_hdr->{$name};
   $prefix = defined($prefix) ? $prefix . ' sha1:' : 'sha1:';
   $r_hdr->{$name} = $prefix . $value;
}

sub calc_cancel_key($$) {
   my ( $user, $message_id ) = @_;
   return MIME::Base64::encode(Digest::HMAC_SHA1::hmac_sha1($message_id, $user . $CANCEL_LOCK), '');
}

sub add_cancel_lock($$) {
   my ( $r_hdr, $user ) = @_;
   my $key = calc_cancel_key($user, $r_hdr->{'Message-ID'});
   my $lock = MIME::Base64::encode(Digest::SHA1::sha1($key), '');
   add_cancel_item($r_hdr, 'Cancel-Lock', $lock);
}