CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

SRC_DIR = .
OBJ_DIR = .

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

all: iw_json_printer

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

iw_json_printer: $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(OBJ_DIR)/*.o iw_json_printer
