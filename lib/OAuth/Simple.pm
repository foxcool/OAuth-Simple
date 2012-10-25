package OAuth::Simple;

use 5.010;
use strict;
use warnings;

require LWP::UserAgent;
require JSON;
require Carp;

our $VERSION = '0.05';


sub new {
    my $class = shift;
    my $self = bless {@_}, $class;

    Carp::croak("app_id, secret and postback required for this action")
      unless ($self->{app_id} && $self->{secret} && $self->{postback});

    $self->{ua}   ||= LWP::UserAgent->new();
    $self->{json} ||= JSON->new;
    return $self;
}


sub authorize {
    my ($self, $url, $params) = @_;

    Carp::croak("Authorize method URL required for this action") unless ($url);
    my %params = %$params if $params && %$params;
    $url = URI->new($url);
    $url->query_form(
        client_id     => $self->{app_id},
        response_type => 'code',
        redirect_uri  => $self->{postback},
        %params,
    );
    return $url;
}

sub request_access_token {
    my ( $self, $params ) = @_;

    my %params = %$params if $params && %$params;
    my ( $url, $code, $raw ) = @params{ 'url', 'code', 'raw' };
    Carp::croak("code and url required for this action") unless $code && $url;
    $url = URI->new($url);
    $url->query_form(
        'client_secret' => $self->{secret},
        'client_id'     => $self->{app_id},
        'code'          => $code,
        'redirect_uri'  => $self->{postback},
        %params,
    );
    my $response = $self->{ua}->get($url);
#    return 0 unless $response->is_success;
    return $response->content if $raw;
    my $obj = $self->{json}->decode($response->content);

    return $obj;
}

sub request {
    my ( $self, $url, $access_token, $params ) = @_;

    Carp::croak("url and access_token required for this action")
      unless ($url && $access_token);
    my %params = %$params if $params && %$params;
    $url = URI->new($url);
    $url->query_form(
        access_token => $access_token,
        %params,
    );
    my $response = $self->{ua}->get($url);
    return 0 unless $response->is_success;
    my $obj = $self->{json}->decode($response->content);

    return $obj;
}

1;


__END__

=pod

=head1 NAME

OAuth::Simple - Simple OAuth authorization on your site

=head1 SYNOPSIS

  my $oauth = OAuth::Simple->new(
      app_id     => 'YOUR APP ID',
      secret     => 'YOUR APP SECRET',
      postback   => 'POSTBACK URL',
  );
  my $url = $oauth->authorize( 'https://www.facebook.com/dialog/oauth', {scope => 'email'} );
  # Your web app redirect method.
  $self->redirect($url);
  # Get access_token.
  my $access = $oauth->request_access_token( 'https://graph.facebook.com/oauth/access_token', $args->{code} );
  # Get user profile data.
  my $profile_data = $oauth->request(
      'https://graph.facebook.com/me',
      $access_token,
  );  


=head1 DESCRIPTION

Use this module for input VK OAuth authorization on your site

=head1 METHODS

=head2 new

  my $oauth = OAuth::Simple->new(
      app_id     => 'YOUR APP ID',
      secret     => 'YOUR APP SECRET',
      postback   => 'POSTBACK URL',
  );

The C<new> constructor lets you create a new B<OAuth::Simple> object.

=head2 authorize

	my $url = $oauth->authorize( $authorize_server_url, {option => 'value'} );
	# Your web app redirect method.
	$self->redirect($url);

This method returns a URL, for which you want to redirect the user.

=head3 Options

See information about options on your OAuth server.

=head3 Response

Method returns URI object.

=head2 request_access_token

  my $access = $oauth->request_access_token( $server_url, $args->{code} );

This method gets access token from OAuth server.

=head3 Options

code - returned in redirected get request from authorize API method.

=head3 Response

Method returns HASH object.

=head2 request

  my $profile_data = $oauth->request(
      $api_method_url,
      $access_token,
      {
	    option => 'value',
      }
  );

This method sends requests to OAuth server.

=head3 Options

url (required)          - api method url;
params (not required)   - other params;
access_token (required) - access token.

=head3 Response

Method returns HASH object with requested data.


=head1 SUPPORT

Github: https://github.com/Foxcool/OAuth-Simple

Bugs & Issues: https://github.com/Foxcool/OAuth-Simple/issues

=head1 AUTHOR

Copyright 2012 Alexander Babenko.

=cut
