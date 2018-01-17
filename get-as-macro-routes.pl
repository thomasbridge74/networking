#!/usr/bin/perl

use Net::IRR;
use Getopt::Long;
use strict;

my $VERBOSE = 0;

my $host = 'whois.radb.net';
my $as_set = "AS-NETSOURCE";


my $result = GetOptions("verbose" => \$VERBOSE);

# Always access ARGV after calling GetOptions

if($ARGV[0]) {
	$as_set = $ARGV[0];
} 

# Moved the connection statement down as it makes more sense to only 
# set the values when all the inputs are defined.

my $connection = Net::IRR->connect( host => $host) || die "Cannot connect to $host\n";

my @routes = get_routes_for_as_set($as_set);

my $prefix_list_name = $as_set;
my $route;

foreach $route (sort @routes) {
	print "ip prefix-list $prefix_list_name permit $route\n";
} 


sub get_routes_for_as_set {
	my ($as_set) = @_;
	my @aslist;
		
	if(!(@aslist = $connection->get_as_set($as_set, 1))) {
		print STDERR "Looking up $as_set\n";
		print STDERR "none found\n";
		return undef;
	}

	my @routes;
	my $as_num;
	
	foreach $as_num (@aslist) {
		@routes = uniq(@routes, $connection->get_routes_by_origin($as_num));
		if($VERBOSE) {
			print "After looking for $as_num we now have found $#routes\n";
			print join "\n", @routes;
			print "\n";
		}
	}

	return(@routes);
}

sub uniq {
	my %seen;
	grep !$seen{$_}++, @_;
}

