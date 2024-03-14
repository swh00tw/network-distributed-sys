# Compiler and flags
CC = g++
CFLAGS = -Wall -Wextra

# Source files
SRCS = process.cpp stopall.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Executable
ALLEXEC	= process stopall

.cpp.o:
	$(CC) $(CFLAGS) -c $<

# Build rules
all: $(ALLEXEC)

clean:
	rm -f *.o $(ALLEXEC)
