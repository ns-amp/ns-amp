find_library(RELIC relic HINTS /usr/local/lib)
find_library(GMP gmp HINTS /usr/loca/lib)
add_executable(bench bench.c util.c vector.c)
target_link_libraries(bench ${RELIC} ${GMP})