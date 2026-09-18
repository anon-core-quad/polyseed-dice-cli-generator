CC      := gcc
CFLAGS  := -g -Wall
LDLIBS  := -lpolyseed -lutf8proc -lsodium -lcrypto

SRC_DIR   := src
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/polyseed-dice-generator

SRCS := $(SRC_DIR)/main1.c \
        $(SRC_DIR)/pbkdf2.c

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJS:.o=.d)

clean:
	rm -rf $(BUILD_DIR)
