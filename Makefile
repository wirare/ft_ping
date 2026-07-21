# Compiler and flags
CXX := clang
OPT_FLAGS := -O3 -march=native -mtune=native -funroll-loops -fvectorize -ffp-contract=fast -freciprocal-math -ffast-math -fstrict-aliasing -flto=full -mprefer-vector-width=256 -fomit-frame-pointer

CXXFLAGS := -Wall -Werror -Wextra -g#-pthread $(OPT_FLAGS)
CPPFLAGS := -Iincludes

# Directories
SRCDIR := srcs
OBJDIR := .objs

# Target binary
TARGET := ft_ping

# Source and object files
SRCFILES := $(wildcard $(SRCDIR)/*.c)
OBJFILES := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCFILES))

# Default target
all: $(TARGET)

# Link object files into final binary
$(TARGET): $(OBJFILES)
	@echo "Linking $(TARGET)..."
	$(CXX) $(CXXFLAGS) $(OBJFILES) -o $(TARGET)

# Compile .c to .o
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

# Create object directory if it doesn't exist
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Clean build files
clean:
	rm -rf $(OBJDIR)

# Clean everything including binary
fclean: clean
	rm -f $(TARGET)

# Rebuild from scratch
re: fclean all

.PHONY: all clean fclean re

