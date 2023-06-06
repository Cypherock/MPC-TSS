CC = cc

CFLAGS  = -Wall -O3 -g
CFLAGS += -DUSE_BN_PRINT=1
INC = -Iinclude

SRCDIR = src
BUILDDIR = build

SOURCES  = bignum.c memzero.c sha2.c main.c
SOURCES += ot.c

OBJECTS = $(addprefix $(BUILDDIR)/, $(SOURCES:.c=.o))

TARGET = poc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(INC) -o $(BUILDDIR)/$(TARGET) $(OBJECTS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

clean:
	rm -f $(TARGET) $(OBJECTS)
