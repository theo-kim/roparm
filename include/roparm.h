#ifndef ROPARM
#define ROPARM

#include "capstone/capstone.h"

// Argument structure
typedef struct {
    char *filename;
    int gadget_length;
} args_t;

typedef struct {
    
} gadget_t;

// Parse arguments, return -1 is error, else return 0 if the filename
//      was included and 1 if to expect the file from stdin
int parse_arguments(int argc, char **argv, args_t *args);

// Load the binary into the buffer and return the length of the buffer
int load_binary_from_file(char *filename, char **buffer);
int load_binary_from_stdin(char **buffer);

// Find return instructions, return number of instructions found
int find_return(cs_insn *capstone_instructions, cs_insn **return_instructions);

// Find gadgets based on the instructions found in the previous step,
int find_gadgets(cs_insn *capstone_instructions, cs_insn *return_instructions, 
    int instruction_n, int gadget_length, gadget_t **gadgets);

// Print gadgets onto STDOUT
void print_gadgets(gadget_t *gadgets, int number_gadgets);

#endif