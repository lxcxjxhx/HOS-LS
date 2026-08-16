#!/usr/bin/env perl

use strict;
use warnings;
use Class::Struct qw(struct);

struct(Package => [
    qualified_name => '$',
    short_name     => '$',
    name_length    => '$',
    repo_idx       => '$',
    priority       => '$',
]);

# "main" is not mentioned by name in the input file
my %ubuntu_repo_idx = (universe => 1, multiverse => 2, restricted => 3);

# qualified package name -> Package
sub parse_package {
    my ($qualified_name) = @_;

    $qualified_name =~ m#^([^/]+).*/([^/]+)$# or die;
    my ($prefix, $short_name) = ($1, $2);

    # "main" repository gets index 0
    my $repo_idx = $ubuntu_repo_idx{$prefix} || 0;

    return Package->new(
        qualified_name => $qualified_name,
        short_name     => $short_name,
        name_length    => length($short_name),
        repo_idx       => $repo_idx,
        priority       => undef, # filled in later
    );
}

# (Package, Package) -> int
sub cmp_packages {
    # A file may be in multiple packages, so we need to choose the "best" one.
    # To further improve this, we could use data from Popularity Contest.
    my ($a, $b) = @_;

    return (
        # Prefer main over universe, universe over multiverse, etc.
        $a->repo_idx      <=> $b->repo_idx      or
        # Prefer packages with short names since they are less likely to be
        # exotic.
        $a->name_length   <=> $b->name_length   or
        # Finally, as a tie breaker, order the packages by their short name. We
        # prefer "greatest" names, so we're likely to pick the greatest version
        # when packages have version numbers in their names.
        $b->short_name    cmp $a->short_name
    );
}

my %file_packages; # file (no leading slash) => list of qualified package names
my %directories; # directory => qualified package name => 1

# Process the input file, populating the above two hashes.
while (<>) {
    /^(.*\S)\s+(\S+)$/ or die;
    my ($file, @packages) = ($1, split /,/, $2);

    # Only include interesting files. This keeps the database size down.
    next unless
        $file =~ /\.h$/ or            # C/C++ headers
        $file =~ /\.hpp$/ or          # C++ headers
        $file =~ /\.hxx$/ or          # C++ headers
        $file =~ /\.hh$/ or           # C++ headers
        $file =~ m#/include/# or      # Headers or other library code
        $file =~ /\.pc$/ or           # pkg-config description files
        $file =~ /\.cmake$/ or        # CMake helper scripts
        $file =~ /\.m4$/ or           # autoconf includes
        $file =~ /\.py$/ or           # Python libraries or scripts
        $file =~ /\.pri$/ or          # QT modules
        $file =~ /\.prf$/ or          # QT spec files
        $file =~ /\.dll$/ or          # Mono/.NET libraries
        $file =~ /\.a$/ or            # static libraries
        $file =~ /\.o$/ or            # static one-file libraries
        $file =~ /\.so[0-9.]*$/ or    # dynamic libraries
        $file =~ m#\bs?bin/[^/]+$# or # executables
        # File names that may be symlinks to directories:
        $file =~ m#/include/[-_a-z0-9/]+$# or
        $file =~ m#/lib/[-_a-z0-9]+$# or
        $file =~ m#/share/[-_a-z0-9]+$#;

    # Files that tend to cause unintended installations
    next if
        $file eq "usr/bin/cmake-gui" or
        $file eq "usr/bin/ccmake";

    # Linux kernels take up too much space in the db
    next if
        $file =~ m#^usr/src/# or
        $file =~ m#^lib/modules/#;

    # Packages that we don't want installed
    @packages = grep {
        $_ !~ /\/python3\.9/ and # binary incompatibility with libs from OS's 3.8
        $_ !~ /\/flang-\d+$/ and # doesn't work with `cmake -E cmake_copy_f90_mod`
        $_ !~ /\/python3?-apport$/ and # leads to confusing Python backtraces
        $_ !~ /\/safe-rm$/ and # installs /usr/*bin/rm
        $_ !~ /\/python-wxgtk.*4\.0$/ and # conflicts with 3.0
        $_ !~ /\/libglewmx-dev$/ and # broken according to Blender devs
        $_ !~ /\/s?ccache$/ and # doesn't work with our tracer
        $_ !~ /nvidia-cuda/ and # doesn't work with gcc 6
        $_ !~ /\/libcuda\d+-/ and # doesn't work with gcc 6
        $_ !~ /freebsd/ and # overlap with standard packages
        $_ !~ /\/libcodcif/ and # contains overly generic file names
        $_ !~ /\/libregfi-dev$/ and # contains overly generic file names
        $_ !~ /\/libowfat-dev$/ and # contains overly generic file names
        $_ !~ /\/libodb-api-dev$/ and # overly generic file names since 18.10
        $_ !~ /\/libstdc\+\+-.*-dev-.*-cross$/ and # can be installed by clang while probing, but then leads to an error
        $_ !~ /\/libbenchmark-dev$/ # this package is broken, and should usually be optional any way
    } @packages;

    next if @packages == 0;
    die if $file =~ /\t/;

    push @{$file_packages{$file}}, @packages;

    my $dir = $file;
    while ($dir =~ s#/[^/]+$## and not $directories{$dir}) {
        foreach my $package (@packages) {
            $directories{$dir}{$package} = 1;
        }
    }
}

# Build the set of all package names so we only have to analyse each package
# name once.
my %all_packages; # qualified package name => 1
foreach my $packages (values %file_packages) {
    foreach my $package (@$packages) {
        $all_packages{$package} = 1;
    }
}

# Sort all packages with the preferred ones first
my @ordered_packages = # Package list
    sort { cmp_packages($a, $b) }
    map { parse_package($_) }
    keys %all_packages;

# Create a map from package names to `Package` structs, populating the
# `priority` field of each struct in the process.
my %package_data; # qualified package name => Package
foreach my $i (0 .. $#ordered_packages) {
    my $data = $ordered_packages[$i];
    $data->priority($i);
    $package_data{$data->qualified_name} = $data;
}

# qualified package name list -> Package
sub preferred_package_data {
    die if @_ == 0;
    my $best;
    foreach my $package (@_) {
        my $data = $package_data{$package};
        if (!$best or $data->priority < $best->priority) {
            $best = $data;
        }
    }
    return $best;
}

# If a _file_ in one package coincides with a _directory_ in another package
# then the file is a symlink, and the packages are in conflict. If the best
# package containing the directory has priority over the best package
# containing the symlink, then we remove the symlink from the database to
# ensure that this lower-priority package will not accidentally get installed.
while (my ($file, $packages) = each %file_packages) {
    if (my $conflicting_packages = $directories{$file}) {
        if (preferred_package_data(@$packages)->priority >
            preferred_package_data(keys %$conflicting_packages)->priority)
        {
            delete $file_packages{$file}; # doesn't invalidate iteration
        }
    }
}

# Join `%file_packages` with `%package_data` to produce a map from package
# names to their contents with no overlap between the files in packages.
my %contents; # short package name => list of files in no particular order
while (my ($file, $packages) = each %file_packages) {
    my $package = preferred_package_data(@$packages)->short_name;
    push @{$contents{$package}}, $file;
}

# Manual additions for files that not stored in the packages directly but
# symlinked by the Debian _alternatives_ mechanism.
push @{$contents{"libwxgtk3.0-gtk3-dev"}}, "usr/bin/wx-config";
push @{$contents{"lua5.2"}}, "usr/bin/luac";
push @{$contents{"bison"}}, "usr/bin/yacc";
push @{$contents{"lzip"}}, "usr/bin/lzip";
push @{$contents{"iptables"}}, "sbin/iptables", "sbin/ip6tables";
foreach my $file (qw(
        rst-buildhtml rst2html rst2html4 rst2html5 rst2latex rst2man rst2odt
        rst2odt_prepstyles rst2pseudoxml rst2s5 rst2xetex rst2xml rstpep2html
)) {
    push @{$contents{"python-docutils"}}, "usr/bin/$file";
}
foreach my $file (qw(
        sphinx-apidoc sphinx-autogen sphinx-build sphinx-quickstart
)) {
    # These binaries are symlinked into /usr/bin by a post-install script
    # because they used to be provided by multiple packages. They're only
    # provided by one package in Ubuntu 20.04, so perhaps these symlinks will
    # go away in a future version.
    push @{$contents{"python3-sphinx"}}, "usr/bin/$file";
}

# Sorted for reproducibility
foreach my $dir (sort keys %directories) {
    print "/$dir\n";
}
print "\n";

foreach my $package (sort keys %contents) {
    print "$package\n";
    print "/$_\n" for sort @{$contents{$package}};
    print "\n";
}
