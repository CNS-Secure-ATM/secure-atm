CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I ../include
SRC      = ../src/main.cpp
TARGET   = main

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
