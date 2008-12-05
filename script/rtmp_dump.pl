#!/usr/bin/env perl

use strict;
use warnings;
use FindBin::libs;

use Pod::Usage;
use Getopt::Long;

use Sniffer::RTMP;
use JSON::Syck;

GetOptions(
    \my %option,
    qw/help port=i/
);
pod2usage(0) if $option{help};

my $dev = $ARGV[0] or pod2usage(1);

sub log_method {
    my ($dir, $packet, $method, $id, $args) = @_;

    my $type = $packet->type == 0x14 ? 'invoke' : 'notify';

    print $dir eq 'in' ? '<=' : '=>';
    print " [$type]";
    print " method:$method";
    print " id:$id";

    if (@$args) {
        my $args = join ', ', map { JSON::Syck::Dump($_) } @$args;
        print " args:$args";
    }
    print "\n";
}

sub log_other {
    my $type = shift;

    return sub {
        my ($dir, $packet) = @_;
        print $dir eq 'in' ? '<=' : '=>';
        print " [${type}]\n";
    };
};

Sniffer::RTMP->new(
    $option{port} ? (filter => "tcp port $option{port}") : (),
    device    => $dev,
    callbacks => {
        notify => \&log_method,
        invoke => \&log_method,
        map { $_ => log_other($_) }
            qw/
            chunk_size
            bytes_read
            ping
            server_bw
            client_bw
            audio
            video
            flex_stream
            flex_shared_object
            flex_message
            shared_object
            flv_data
            unknown
            /,
    },
)->run;

=head1 NAME

rtmp_dump.pl - example script to dump rtmp packet

=head1 SYNOPSIS

=head1 AUTHOR

Daisuke Murase <typester@cpan.org>

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=cut

1;
