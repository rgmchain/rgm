add_library(memenv STATIC ../helpers/memenv/memenv.cc)
target_include_directories(memenv PRIVATE .. ../include)
target_link_libraries(memenv leveldb)
