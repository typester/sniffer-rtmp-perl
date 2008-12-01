package Sniffer::RTMP::Session;
use Moose;

use NetPacket::TCP;

use Kamaitachi::IOStream;
use Data::AMF;

has sequence_start => is => 'rw';
has ack_start      => is => 'rw';
has src_port       => is => 'rw';
has dest_port      => is => 'rw';
has status         => is => 'rw';

has handshaked => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { { in => 0, out => 0 } },
);

has tcp => (
    is  => 'rw',
    isa => 'NetPacket::TCP',
);

has window => (
    is      => 'rw',
    isa     => 'HashRef',
    lazy    => 1,
    default => sub { { src => {}, dest => {} } },
);

has dummy_socket => (
    is      => 'rw',
    isa     => 'Object',
    lazy    => 1,
    default => sub { bless {} },
);

has in_io => (
    is      => 'rw',
    isa     => 'Kamaitachi::IOStream',
    lazy    => 1,
    default => sub {
        Kamaitachi::IOStream->new( socket => shift->dummy_socket );
    },
);

has out_io => (
    is      => 'rw',
    isa     => 'Kamaitachi::IOStream',
    lazy    => 1,
    default => sub {
        Kamaitachi::IOStream->new( socket => shift->dummy_socket );
    },
);

has parser => (
    is      => 'rw',
    isa     => 'Object',
    lazy    => 1,
    default => sub { Data::AMF->new },
);

has context => (
    is       => 'rw',
    isa      => 'Sniffer::RTMP',
    weak_ref => 1,
    handles  => ['callbacks'],
);

has packet_names => (
    is      => 'rw',
    isa     => 'ArrayRef',
    default => sub {[
        undef,
        'chunk_size',           # 0x01
        undef,                  # 0x02
        'bytes_read',           # 0x03
        'ping',                 # 0x04
        'server_bw',            # 0x05
        'client_bw',            # 0x06
        undef,                  # 0x07
        'audio',                # 0x08
        'video',                # 0x09
        undef, undef, undef, undef, undef, # 0x0a - 0x0e
        'flex_stream',                     # 0x0f
        'flex_shared_object',              # 0x10
        'flex_message',                    # 0x11
        'notify',                          # 0x12
        'shared_object',                   # 0x13
        'invoke',                          # 0x14
        undef,                             # 0x15
        'flv_data',                        # 0x16
    ]},
);

sub new_from_packet {
    my ($self, $tcp) = @_;

    $self->sequence_start( $tcp->{seqnum} );
    $self->ack_start( $tcp->{acknum} );
    $self->src_port( $tcp->{src_port} );
    $self->dest_port( $tcp->{dest_port} );

    $self;
}

sub handle_packet {
    my ($self, $tcp, $timestamp) = @_;

    if ($self->flow eq '-:-') {
        $self->new_from_packet($tcp);
    }
    if ($self->ack_start == 0 and $tcp->{acknum}) {
        $self->ack_start( $tcp->{acknum} );
    }

    my $key = $self->flow;
    my @dir = qw/src dest/;
    if ($self->signature($tcp) ne $key) {
        @dir = reverse @dir;
    }

    $self->window->{ $dir[0] }->{ $tcp->{seqnum} } = $tcp;
    $self->flush_window( $dir[1], $tcp->{acknum} );
}

sub flush_window {
    my ($self, $part, $ack) = @_;
    my $status = $self->status;

    my $window  = $self->window->{ $part };
    my @seqnums = grep { $_ <= $ack } (sort keys %$window);

    my @packets = map { delete $window->{ $_ } } @seqnums;
    for my $tcp (@packets) {
        die unless $tcp;

        if (not defined $status) {
            if ($tcp->{flags} == SYN) {
                $self->new_from_packet($tcp);
                $self->status('SYN');
                return;
            }
            else {
                return;
            }
        }
        elsif ($status eq 'SYN') {
            if ($tcp->{flags} == SYN+ACK) {
                $self->status("SYN_ACK");
                return;
            }
            else {
                return;
            }
        }
        elsif ($status eq 'ACK' or $status eq 'SYN_ACK') {
            my $data = $tcp->{data};
            my $key  = $self->flow;

            if (length $data) {
                my $dir    = $self->flow eq $self->signature($tcp) ? 'out' : 'in';
                my $ioname = "${dir}_io";
                my $io  = $self->$ioname;

                $io->push($data);

                $self->process_packet( $dir => $io );
            }
            $self->status('ACK') unless $status eq 'ACK';
        }
        elsif ($status eq 'CLOSE') {
            return;
        }

        if ($tcp->{flags} & FIN) {
            $self->status('CLOSE');
        }
    }
}

sub process_packet {
    my ($self, $dir, $io) = @_;

    unless ($self->{handshaked}{$dir}) {
        my $packet = $io->read(1 + 0x600*2) or $io->reset;
        if ($packet) {
            $io->spin;
            $self->{handshaked}{$dir}++;
        }
    }

    if ($self->{handshaked}{$dir}) {
        while (my $packet = $io->get_packet) {
            next if $packet->size > bytes::length($packet->data);

            $self->dispatch( packet => $dir => $packet );

            my $type = $self->packet_names->[ $packet->type ] || 'unknown';

            if ($packet->type == 0x14 or $packet->type == 0x12) { # invoke or notify
                my ($method, $id, @args);
                eval { ($method, $id, @args) = $self->parser->deserialize( $packet->data ) };
                confess qq{parse error '$@'} if $@;
                $self->dispatch( $type => $dir => $packet, $method, $id, \@args );
            }
            elsif ($packet->type == 0x01) { # chunksize
                $io->chunk_size(unpack('N', $packet->data));
                $self->dispatch( $type => $dir => $packet );
            }
            else {
                $self->dispatch( $type => $dir => $packet );
            }
        }
    }
}

sub dispatch {
    my ($self, $name, $dir, $packet, @args) = @_;
    my $cb = $self->callbacks->{$name};
    return unless $cb and ref($cb) eq 'CODE';

    $cb->($dir, $packet, @args);
}

sub flow {
  my ($self) = @_;
  join ":", ($self->src_port||"-"), ($self->dest_port||"-")
};

sub signature {
  my ($class,$packet) = @_;
  join ":", $packet->{src_port}, $packet->{dest_port};
};

1;
