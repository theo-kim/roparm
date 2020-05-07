#ifndef ROPARM
#define ROPARM

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "capstone/capstone.h"

#define HELP_MESSAGE "Format: roparm [<argument> <value>] \n\
\t-h\tdisplay this message (no value)\n\
\t-f\tspecify binary file to load\n\
\t-l\tspecify length of the gadget\n\
\t-m\tspecify the mode of operation (THUMB or ARM) to find gadgets for\n"

// Argument flags
#define FILE_FLAG       'f'
#define GADGET_LEN_FLAG 'l'
#define HELP_FLAG       'h'
#define MODE_FLAG       'm'

// Error messages
#define ERROR_INCORRECT_ARGS    "Incorrect number of arguments, run roparm -h for complete list"
#define ERROR_EXPECT_VALUE      "Provided an argument flag when expecting an argument"
#define ERROR_VALUE_NOT_NEED    "You provided a value for an argument that doesn't need one"
#define ERROR_UNKNOWN_FLAG      "Unknown flag symbol provided"
#define ERROR_MISSING_LEN       "You must define a gadget length"
#define ERROR_NON_ZERO_LEN      "You must define a gadget length greater than zero"
#define ERROR_UNKNOWN_NUMBER    "Unknown number provided"
#define ERROR_UNKNOWN_FILE      "Unknown filename"
#define ERROR_EMPTY_FILE        "Target file is empty"
#define ERROR_NOT_ELF           "Target file is not in ELF format"
#define ERROR_NOT_EXEC_DYN      "This tool only supports ELF executables or shared libraries"
#define ERROR_NOT_ARM           "This file is not an ARM file, make sure that target file is compiled for ARM"
#define ERROR_64BIT             "64 Bit binary... does ARM even support that?"
#define ERROR_UNKNOWN_MODE      "Unknown ARM operating mode"

// Enums
#define ENUM_ARGUMENT   -1
#define ENUM_FILENAME   0
#define ENUM_GADGET_LEN 1
#define ENUM_MODE       2

#define ENUM_LOAD_STDIN 1
#define ENUM_LOAD_FILE  2

// Constants
#define BUFFER_SIZE     128

// Print color macros
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define CONSOLE_COLOR(color, text) color text ANSI_COLOR_RESET

// Error reporting
void report_error(const char *msg);

void report_error_with_insert(const char *msg, char *insert);

// Argument structure
typedef struct {
    char *filename;
    int gadget_length;
    uint64_t start_address;
    int thumb_mode;
} args_t;

// Text section structure
typedef struct {
    uint8_t *bytes;
    uint64_t entry_address;
    int type;
    int size;
    int little_endian;
    int is_thumb;
} elf_t;

// Type for a gadget
typedef struct {
    cs_insn *start;
    int gadget_len;
    int is_thumb;
} gadget_t;

// Parse arguments, return -1 is error, else return 0 if the filename
//      was included and 1 if to expect the file from stdin
int parse_arguments(int argc, char **argv, args_t *args);

// Load the binary into the buffer and return the length of the buffer
int load_binary_from_file(char *filename, uint8_t **buffer);
int load_binary_from_stdin(uint8_t **buffer);

// Parse ELF
int extract_text(uint8_t *binary_buffer, size_t buffer_len, elf_t *text_section);

// Find return instructions, return number of instructions found
int find_return(csh handle, cs_insn *capstone_instructions, int instruction_count, cs_insn ***return_instructions);

// Find gadgets based on the instructions found in the previous step,
int find_gadgets(cs_insn **return_instructions, int instruction_n, int gadget_length, gadget_t **gadgets);

// Print gadgets onto STDOUT
void print_gadgets(gadget_t *gadgets, int number_gadgets);

#endif