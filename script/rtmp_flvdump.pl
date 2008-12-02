#!/usr/bin/env perl

use strict;
use warnings;
use FindBin::libs;

use Pod::Usage;
use Getopt::Long;

use Sniffer::RTMP;
use JSON::Syck;

use Data::AMF::IO;

use Time::HiRes qw/gettimeofday tv_interval/;

GetOptions(
    \my %option,
    qw/help/
);
pod2usage(0) if $option{help};

my $dev    = $ARGV[0] or pod2usage(1);
my $output = $ARGV[1] or pod2usage(1);

my $elapsed_video = 0;
my $elapsed_audio = 0;

open my $fh, ">$output" or die $!;
END { close $fh }

# write flv header
print $fh 'FLV';
print $fh pack('C', 1);
print $fh pack('C', 0b00000101);
print $fh pack('N', 9);
print $fh pack('N', 0);

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

        return unless $dir eq 'in';

        if ($packet->type == 0x08 or $packet->type == 0x09) {
            my $io = Data::AMF::IO->new;

            # packet type
            $io->write_u8( $packet->type );

            # packet data size
            $io->write_u24( $packet->size );

            # relative timestamp
            if ($packet->type == 0x08) {
                $elapsed_audio += $packet->timer;
                $io->write_u24($elapsed_audio);
                $io->write_u8($elapsed_audio>>24);
            }
            else {
                $elapsed_video += $packet->timer;
                $io->write_u24($elapsed_video);
                $io->write_u8($elapsed_video>>24);
            }

            $io->write_u24(0);
            $io->write( $packet->data );

            $io->write_u32( $packet->size + 11 );

            print $fh $io->data;
        }
        elsif ($packet->type == 0x16) {
            print $fh $packet->data;
        }
    };
};

Sniffer::RTMP->new(
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

