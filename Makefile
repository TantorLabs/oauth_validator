# contrib/oauth_validator/Makefile
 
PGFILEDESC = "oauth_validator - OAuth validator"
MODULE_big = oauth_validator
 
OBJS = \
    $(WIN32RES) \
    oauth_validator.o \
    token_utils.o
 
PG_CPPFLAGS += -I$(top_srcdir)/src/common
PG_CPPFLAGS += -I$(libpq_srcdir)
 
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS) 
