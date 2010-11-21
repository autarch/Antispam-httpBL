package Antispam::httpBL;

use strict;
use warnings;
use namespace::autoclean;

use Antispam::Toolkit::Result;
use MooseX::Types::Moose qw( Str );
use WWW::Honeypot::httpBL;

use Moose;
use MooseX::StrictConstructor;

with 'Antispam::Toolkit::Role::UserChecker';

has access_key => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

sub check_user {
    my $self = shift;
    my %p    = @_;

    return unless $p{ip};

    my $hp
        = WWW::Honeypot::httpBL->new( { access_key => $self->access_key() } );

    $hp->fetch( $p{ip} );

    my @details;

    push @details, 'IP address is a comment spammer'
        if $hp->is_comment_spammer();
    push @details, 'IP address is an email harvester'
        if $hp->is_harvester();
    push @details, 'IP address is suspicious'
        if $hp->is_suspicious();
    push @details, 'IP address threat score is ' . $hp->threat_score();
    push @details, 'Days since last activity for this IP: '
        . $hp->days_since_last_activity();

    # See http://www.projecthoneypot.org/threat_info.php - a score that's much
    # above 75 is ridiculously unlikely, so we'll just treat >= 75 as a 10.
    my $score = $hp->threat_score() > 75 ? 10 : $hp->threat_score() / 7.5;

    return Antispam::Toolkit::Result->new(
        score   => $score,
        details => \@details,
    );
}

{
    unless ( WWW::Honeypot::httpBL->can('days_since_last_activity') ) {
        *WWW::Honeypot::httpBL::days_since_last_activity
            = \&WWW::Honeypot::httpBL::days_since_last_actvity;
    }
}

__PACKAGE__->meta()->make_immutable();

1;
