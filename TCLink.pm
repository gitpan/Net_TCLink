package Net::TCLink;

require 5.005_62;
use strict;
use warnings;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Net::TCLink ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);
our $VERSION = '3.25';

bootstrap Net::TCLink $VERSION;

sub send
{
	my $params;

	if ($#_ == 0)
	{
		$params = $_[0];
	}
	else
	{
		%$params = @_;
	}

	my $handle = TCLinkCreate();
	foreach (keys %$params) 
	{
		TCLinkPushParam($handle,$_,$params->{$_});
	}

	TCLinkSend($handle);

	my %response;
	my $buf = TCLinkGetEntireResponse($handle);
	my @parts = split/\n/,$buf;
	foreach (@parts) 
	{
			my ($name,$val) = split/=/,$_;
			$response{$name} = $val;
	}

	return %response;
}

1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

Net::TCLink - Perl interface to the TrustCommerce payment gateway

=head1 SYNOPSIS

  use Net::TCLink;
  %results = Net::TCLink::send(%params);

=head1 DESCRIPTION

Net::TCLink is a module that allows for fast, secure, reliable credit 
card and check transactions via the TrustCommerce IP gateway.  The 
module consists of a single functions call that accepts a hash that 
describes the requested transaction and returns a map that describes the 
result.  What values can be passed and returned are beyond the scope of 
this document and can be found in the web developers guide.  This guide 
is included the Net::TCLink distribution as TCDevGuide.{txt,html} or can 
be found at https://vault.trustcommerce.com/.

=head2 EXPORT

None by default.

=head1 AUTHOR

Orion Henry, orion@trustcommerce.com

=head1 SEE ALSO

perl(1).

=cut
