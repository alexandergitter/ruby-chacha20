require "mkmf"

$CFLAGS << " -Wall -funroll-loops"
$CFLAGS << " -Wextra -O0 -ggdb3" if ENV["DEBUG"]

create_makefile("chacha20_bindings")
