CC = g++
CFLAGS = -lpcap
TARGET = send_arp

SRC_DIR = src
INCLUDE_DIR = include
BINARY_DIR = bin

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.cpp, %.o, $(wildcard $(SRC_DIR)/*.cpp))
HEADERS = $(wildcard $(INCLUDE_DIR)/*.h)

$(TARGET): $(OBJECTS)
	@mkdir -p $(BINARY_DIR)
	@echo "[+] Make Binary File"
	@$(CC) $(CFLAGS) -o $(BINARY_DIR)/$@ $(OBJECTS)

%.o: %.cpp $(HEADERS)
	@echo "[+] Compile $< File"
	@$(CC) $(CFLAGS) -c -o $@ $< -I$(INCLUDE_DIR)

clean:
	@rm -f $(BINARY_DIR)/$(TARGET)
	@rmdir $(BINARY_DIR) 2> /dev/null
	@rm -f $(SRC_DIR)/*.o

