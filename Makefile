CC=g++
AR=ar
C=gcc
CFLAGS=-Wall -Ilibquic/src -Ilibquic/src/third_party/protobuf/src  -DUSE_OPENSSL=1 -Iboringssl/include -g -gdwarf-4
CPPFLAGS=--std=gnu++11
CPP_FILES:=$(wildcard src/*.cc)
CPP_BASE_FILES:=$(CPP_FILES:src/%=%)
#C_FILES:=$(wildcard src/*.c)
#C_BASE_FILES:=$(C_FILES:src/%=%)
OBJ_FILES:=$(addprefix build/,$(CPP_BASE_FILES:.cc=.o))
#OBJ_FILES:=$(addprefix build/,$(CPP_BASE_FILES:.cc=.o)) $(addprefix build/,$(C_BASE_FILES:.c=.o))
LIB_FILE=libgoquic.a

all: $(OBJ_FILES) $(LIB_FILE)

$(LIB_FILE): $(OBJ_FILES)
	$(AR) rvs $@ $(OBJ_FILES)

#build/%.o: src/%.c
#	mkdir -p $(dir $@)
#	$(C) $(CFLAGS) -c -o $@ $<

build/%.o: src/%.cc
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f build/*
	rm -f libgoquic.a
