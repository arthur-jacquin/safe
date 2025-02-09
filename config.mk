# safe version
VERSION = 0.1

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

# flags
CPPFLAGS =
#CFLAGS   = -g -std=c99 -pedantic -Wall -O0
CFLAGS   = -std=c99 -pedantic -Wall -Wno-deprecated-declarations -Os
LDFLAGS  = -static

# compiler and linker
CC = cc
