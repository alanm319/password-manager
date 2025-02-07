# Compiler
CXX = clang++

# Compiler flags
CXXFLAGS = -std=c++20 -Wall -Wextra -Iinclude $(shell pkg-config --cflags sqlcipher libsodium)
LDFLAGS  = $(shell pkg-config --libs-only-L sqlcipher libsodium)
LDLIBS   = $(shell pkg-config --libs-only-l sqlcipher libsodium)

# source and target
SRC    = $(wildcard src/*.cpp)
OBJECTS = $(patsubst src/%.cpp, build/%.o, $(SRC))
TARGET = build/password_manager

# build
all: $(TARGET)

# linke the exec
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS) $(LDLIBS)

# compile the source files to .o files
build/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f build/password_manager build/*.o