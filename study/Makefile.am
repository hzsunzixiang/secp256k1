# Defines which program executables will be produced.
#bin_PROGRAMS = test  sign sign1
bin_PROGRAMS = sign1  sign2 sign3

# Defines which source files are used to produce the specificed
# executable.
sign1_SOURCES = sign1.c
sign2_SOURCES = sign2.c
sign3_SOURCES = sign3.c

# Defines flags for the C preprocessor *specific to ``hw``*.
# test_CPPLFAGS = 

# These are instead *default* flags, used by all the programs in
# ``bin_PROGRAMS``.
AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir) -I$(top_srcdir)/include

# Extra options for the linker.
# test_LDFLAGS = 

# Default options for the linker OR for libtool (depending on what you
# put in ``configure.ac``), used by all the programs in
# ``bin_PROGRAMS``.
#
# In this case, we want to statically link the libraries in
# ``test_LDADD`.
AM_LDFLAGS =  $(top_srcdir)/libsecp256k1.la #-static

# Libraries the ``hw`` binary will be linked to.
sign1_LDADD = 
sign2_LDADD = 
sign3_LDADD = 
