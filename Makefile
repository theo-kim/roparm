CC = gcc -std=c11

DISTDIR = ./dist/
NAME = roparm

ODIR = build

IDIR = ./include/
LIBS = -l capstone.4

MAC_LDIR = ./lib/darwin

UBUNTU_LDIR = ./lib/ubuntu

OTHER_LDIR = /usr/local/lib

# WIN32_LDIR = ./lib/windows-x86
# WIN64_LDIR = ./lib/windows-x64

SRC = $(wildcard ./src/*.c)
_OBJ = $(SRC:.c=.o)
OBJ = $(patsubst ./src/%,$(ODIR)/%,$(_OBJ))
DEP = $(OBJ:.o=.d)  # one dependency file for each source

LDFLAGS = $(libincl) $(LIBS)
CXXFLAGS = -Wall -g -I$(IDIR) $(incl)


# DON'T EDIT BELOW THIS LINE

ifeq ($(OS),Windows_NT)
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
        libincl = -L$(WIN64_LDIR)
    else
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
            libincl = -L$(WIN64_LDIR)
        endif
        ifeq ($(PROCESSOR_ARCHITECTURE),x86)
			libincl = -L$(WIN32_LDIR)
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S), Darwin)
		libincl = -L$(MAC_LDIR)
	endif
	ifeq ($(UNAME_S), Linux)
		DIST := $(shell lsb_release -si)
		ifeq ($(DIST), Ubuntu)
			libincl = -L$(MAC_LDIR)
		else
			libincl = -L$(OTHER_LDIR)
		endif
	endif
endif

$(ODIR)/%.o: src/%.c
	if test -d $(ODIR); then echo ""; else mkdir build; fi
	$(CC) -c -o $@ $< $(CXXFLAGS)

default: $(OBJ)
	$(CC) $^ -o $(DISTDIR)$(NAME) $(CXXFLAGS) $(LDFLAGS)

.PHONY: $(NAME)
$(NAME):
	./$(NAME)

-include $(DEP)
$(ODIR)/%.d: src/%.c
	@$(CPP) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean
clean:
	rm -f $(ODIR)/*.o $(ODIR)/*.d ./$(NAME)
.PHONY: cleandeps
cleandeps:
	rm -f $(ODIR)/*.d ./$(NAME)
