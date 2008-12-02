package Sniffer::RTMP;
use Moose;

our $VERSION = '0.01';

use Net::Pcap qw/:functions/;

use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

use Sniffer::RTMP::Session;

has device => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    trigger  => sub {
        my $self = shift;
        pcap_findalldevs(\my %dev, \my $err);
        confess $err if $err;
        confess qq{no such interface "$self->{device}"} unless $dev{ $self->device };
    },
);

has pcap => (
    is  => 'rw',
    isa => 'Object',
);

has filter => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub { 'tcp port 1935' },
);

has callbacks => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { {} },
);

has sessions => (
    is      => 'rw',
    isa     => 'HashRef[Sniffer::RTMP::Session]',
    lazy    => 1,
    default => sub { {} },
);

sub run {
    my $self = shift;

    my $err;
    my $pcap = pcap_open_live( $self->device, 128000, -1, 0, \$err);
    confess qq{Unable to create packet capture on device "$self->{device}"} unless defined $pcap;

    $self->pcap($pcap);

    my ($address, $netmask);
    if (pcap_lookupnet($self->device, \$address, \$netmask, \$err)) {
        confess qq{Unable to look up device information for "$self->{device}" - $err};
    }

    pcap_compile( $pcap, \my $filter, $self->filter, 0, $netmask)
        and confess qq{Unable to compile packet capture filter};
    pcap_setfilter($pcap, $filter);

    pcap_loop($pcap, -1, sub {
        my ($user_data, $header, $packet) = @_;
        $self->handle_eth_packet( $packet, $header->{tv_sec} );
    }, '') or confess qq{Unable to perform packet capture};
}

sub handle_eth_packet {
    my ($self, $eth, $ts) = @_;
    $self->handle_ip_packet( NetPacket::Ethernet->decode($eth)->{data}, $ts || time );
}

sub handle_ip_packet {
    my ($self, $ip_data, $ts) = @_;

    my $ip = NetPacket::IP->decode($ip_data);
    $ip->{hlen} = 5 if $ip->{hlen} < 5;

    $self->handle_tcp_packet(
        substr( $ip->{data}, 0, $ip->{len} - ($ip->{hlen}*4) ),
        $ts,
    );
}

sub handle_tcp_packet {
    my ($self, $tcp, $ts) = @_;
    $tcp = NetPacket::TCP->decode($tcp) unless ref $tcp;

    my $session = $self->find_or_create_session($tcp);
    $session->handle_packet( $tcp, $ts );

    $session;
}

sub find_or_create_session {
    my ($self, $tcp) = @_;

    my $key = join ':', sort $tcp->{src_port}, $tcp->{dest_port};
    unless ($self->sessions->{ $key }) {
        $self->sessions->{ $key } = Sniffer::RTMP::Session->new(
            tcp     => $tcp,
            context => $self,
        );
    }

    $self->sessions->{ $key };
}

=head1 NAME

Sniffer::RTMP - Module abstract (<= 44 characters) goes here

=head1 SYNOPSIS

  use Sniffer::RTMP;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for this module was created by ExtUtils::ModuleMaker.
It looks like the author of the extension was negligent enough
to leave the stub unedited.

Blah blah blah.

=head1 AUTHOR

Daisuke Murase <typester@cpan.org>

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=cut

1;
