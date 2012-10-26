package OAuth::Simple;

use 5.010;
use strict;
use warnings;

require LWP::UserAgent;
require JSON;
require Carp;

our $VERSION = '0.15';


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
    my ($self, $params) = @_;

    my %params = %$params if $params && %$params;
    my $url = delete $params{url};
    Carp::croak("Authorize method URL required for this action") unless ($url);
    $url = URI->new($url);
    $url->query_form(
        client_id     => $self->{app_id},
        redirect_uri  => $self->{postback},
        %params,
    );

    return $url;
}

sub request_access_token {
    my ( $self, $params ) = @_;

    my %params = %$params if $params && %$params;
    my ( $url, $code, $raw, $http_method ) = delete @params{ qw(url code raw http_method) };
    Carp::croak("code and url required for this action") unless $code && $url;
    $url = URI->new($url);
    $url->query_form(
        'client_secret' => $self->{secret},
        'client_id'     => $self->{app_id},
        'code'          => $code,
        'redirect_uri'  => $self->{postback},
        %params,
    );
    my $response = $self->{ua}->request( $self->prepare_http_request($url, $http_method) );
    return 0 unless $response->is_success;
    return $response->content if $raw;
    return $self->{json}->decode($response->content);
}

sub request_data {
    my ( $self, $params ) = @_;

    my %params = %$params if $params && %$params;
    my ( $url, $access_token, $raw, $http_method ) = delete @params{ qw(url access_token raw http_method) };
    Carp::croak("url and access_token required for this action")
      unless ($url && $access_token);
    $url = URI->new($url);
    $url->query_form(
        access_token => $access_token,
        %params,
    );
    my $response = $self->{ua}->request( $self->prepare_http_request($url, $http_method) );
    
    return 0 unless $response->is_success;
    return $response->content if $raw;    
    return $self->{json}->decode($response->content);
}

sub prepare_http_request {
    my ( $self, $url, $method ) = @_;
    
    $method ||= 'GET';
    return HTTP::Request->new( $method, $url );
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
  my $url = $oauth->authorize( {url => 'https://www.facebook.com/dialog/oauth', scope => 'email', response_type => 'code'} );
  # Your web app redirect method.
  $self->redirect($url);
  # Get access_token.
  # Facebook returns data not in JSON. Use the raw mode and parse.
  my $access = $oauth->request_access_token( {url => 'https://graph.facebook.com/oauth/access_token', code => $args->{code}, raw => 1} );
  # Get user profile data.
  my $profile_data = $oauth->request_data( {url => 'https://graph.facebook.com/me', access_token => $access} );  


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

	my $url = $oauth->authorize( {url => $authorize_server_url, option => 'value'} );
	# Your web app redirect method.
	$self->redirect($url);

This method returns a URL, for which you want to redirect the user.

=head3 Options

See information about options on your OAuth server.

=head3 Response

Method returns URI object.

=head2 request_access_token

  my $access = $oauth->request_access_token( {url => $server_url, code => $args->{code}} );

This method gets access token from OAuth server.

=head3 Options

code         - returned in redirected get request from authorize API method;
raw          - do not decode JSON, return raw data;
http_method  - set http method: GET(default), POST, etc.

=head3 Response

Method returns HASH object.

=head2 request_data

  my $profile_data = $oauth->request(
      url          => $api_method_url,
      access_token => $access_token,
      raw          => 1,
      http_method  => 'POST',
      }
  );

This method sends requests to OAuth server.

=head3 Options

url (required)          - api method url;
params (not required)   - other custom params on OAuth server;
access_token (required) - access token;
raw                     - do not decode JSON, return raw data (default 0);
http_method             - set http method: GET(default), POST, etc.

=head3 Response

Method returns HASH object with requested data.

=head2 prepare_http_request

Returns HTTP::Request object.

=head1 SUPPORT

Github: https://github.com/Foxcool/OAuth-Simple

Bugs & Issues: https://github.com/Foxcool/OAuth-Simple/issues

=head1 AUTHOR

Copyright 2012 Alexander Babenko.

=cut
