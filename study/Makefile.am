# Defines which program executables will be produced.
bin_PROGRAMS = test 

# Defines which source files are used to produce the specificed
# executable.
test_SOURCES = test.c

# Defines flags for the C preprocessor *specific to ``hw``*.
# test_CPPLFAGS = 

# These are instead *default* flags, used by all the programs in
# ``bin_PROGRAMS``.
AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include

# Extra options for the linker.
# test_LDFLAGS = 

# Default options for the linker OR for libtool (depending on what you
# put in ``configure.ac``), used by all the programs in
# ``bin_PROGRAMS``.
#
# In this case, we want to statically link the libraries in
# ``test_LDADD`.
AM_LDFLAGS = #-static

# Libraries the ``hw`` binary will be linked to.
test_LDADD = $(top_srcdir)/libsecp256k1.la
