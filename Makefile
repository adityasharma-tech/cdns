CXX = g++
CXXFLAGS = -Wall -g

SRC_DIR = src
BUILD_DIR = dist

CLIENT = $(BUILD_DIR)/client
SERVER = $(BUILD_DIR)/server

CLIENT_OBJ = $(BUILD_DIR)/client.o
SERVER_OBJ = $(BUILD_DIR)/server.o

TARGETS = $(CLIENT) $(SERVER)

.PHONY: all clean

all: $(TARGETS)

$(CLIENT): $(CLIENT_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(SERVER): $(SERVER_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILD_DIR)/client.o: $(SRC_DIR)/client.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/server.o: $(SRC_DIR)/server.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
