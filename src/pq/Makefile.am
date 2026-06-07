noinst_LIBRARIES = librgm_pq.a

librgm_pq_a_SOURCES = \
  pq_key.cpp \
  pq_pubkey.cpp

librgm_pq_a_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  $(BITCOIN_INCLUDES) \
  $(LIBOQS_CFLAGS) \
  -I$(top_srcdir)/src \
  -I$(top_srcdir)/src/config

librgm_pq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
