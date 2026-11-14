#!/usr/bin/env perl
# ADR-007 Decision 7: no force unwrap (`x!`, `T!`), `try!` or `as!` in Swift outside tests.
# Swift has no compiler setting for this, so this check strips comments and string literals
# and looks for a `!` straight after a name, a closing bracket or a generic, not before `=`.
# Usage: swift-unwrap-check.pl FILE...   Exit 1 and list the lines if any are found.
use strict;
use warnings;

my $found = 0;
for my $file (@ARGV) {
    open(my $fh, '<', $file) or die "cannot read $file: $!\n";
    local $/;
    my $src = <$fh>;
    close $fh;
    # Blank out comments and literals, keeping newlines so line numbers stay right.
    my $blank = sub { (my $s = shift) =~ s/[^\n]/ /g; $s };
    $src =~ s{("""[\s\S]*?"""|/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*")}{$blank->($1)}ge;
    my $n = 0;
    for my $line (split /\n/, $src, -1) {
        $n++;
        if ($line =~ /[\w\)\]\}>]!(?!=)/) {
            print "$file:$n: force unwrap, try! or as!\n";
            $found = 1;
        }
    }
}
exit $found;
