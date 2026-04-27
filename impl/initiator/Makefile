######################################################################
# Makefile
######################################################################
CC      := gcc
TARGET  := build/colibri
OBJDIR  := build/obj

SRCS := $(shell find src/ -name '*.c' | sort)
OBJS := $(patsubst src/%.c, $(OBJDIR)/%.o, $(SRCS))

CFLAGS  := -Wall -Wextra -DLOG_USE_COLOR -I include/
DBGFLAGS:= -g3 -DDEBUG
LIBS    := -linih -lssl -lcrypto
LDFLAGS := $(LIBS)

.PHONY: all clean debug noconfig

######################################################################
# Target
######################################################################

all: $(TARGET)

# Link finale
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "[LD]  $@"

# Compilazione incrementale — ogni .c → il suo .o
$(OBJDIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "[CC]  $<"

######################################################################
# Varianti
######################################################################

debug: CFLAGS += $(DBGFLAGS)
debug: $(TARGET)

noconfig: CFLAGS += -DNO_INI_PARSING
noconfig: clean $(TARGET)

clean:
	rm -rf $(OBJDIR) $(TARGET)