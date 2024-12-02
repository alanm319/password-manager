# Compiler
CXX = clang++

# Compiler flags
CXXFLAGS = -std=c++17 $(shell pkg-config --cflags libsodium)
LDFLAGS  = $(shell pkg-config --libs-only-L libsodium)
LDLIBS   = $(shell pkg-config --libs-only-l libsodium)

# source and target
SRC    = main.cpp
TARGET = main

# build
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)