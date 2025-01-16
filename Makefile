# Compiler
CXX = clang++

# Compiler flags
CXXFLAGS = -std=c++17 -Iinclude $(shell pkg-config --cflags libsodium)
LDFLAGS  = $(shell pkg-config --libs-only-L libsodium) -lsqlite3
LDLIBS   = $(shell pkg-config --libs-only-l libsodium)

# source and target
SRC    = $(wildcard src/*.cpp)
OBJECTS = $(patsubst src/%.cpp, build/%.o, $(SRC))
TARGET = password_manager

# build
all: $(TARGET)

# linke the exec
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS) $(LDLIBS)

# compile the source files to .o files
build/%.o: src/%.cpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)