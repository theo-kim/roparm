#include "stdio.h"
#include "capstone/capstone.h"

#include "roparm.h"

int main(int argc, char **argv) {
    args_t args;
    gadget_t *gadgets;
    int operation_mode, binary_buffer_len, instruction_count, return_count,
        gadget_count;
    char *binary_buffer;
    csh handle;
    cs_insn *instructions, *return_instructions;

    // 1. Check for command line arguments and validate
    if ((operation_mode = parse_arguments(argc, argv, &args)) < 0) {
        return 1;
    }
    // 1a. (if file is not provided by argument) Load file from stdin
    if (operation_mode == 1) {
        binary_buffer_len = load_binary_from_file(args.filename, &binary_buffer);
    }
    // 1b. (if file is provided by argument) Open file and load into buffer
    else {
        binary_buffer_len = load_binary_from_stdin(&binary_buffer);
    }
    // 2. Disassemble the provided binary
    // Initialize Capstone Engine
    if (cs_open(CS_ARCH_ARM, CS_MODE_64, &handle) != CS_ERR_OK) {
		return 2;
    }
    // Disassemble
    instruction_count = cs_disasm(handle, binary_buffer, binary_buffer_len, 0x1000, 0, &instructions);
    if (instruction_count <= 0) {
        fprintf(stderr, "Could not disassemble supplied binary.\n");
        return 3;
    }
    // 3. Scan the file and search for return statements
    //    in ARM, there is not RET instruction, so we need to look for any 
    //    instruction that writes to the PC register.
    return_instructions = find_return(instructions, &return_instructions);
    if (return_instructions <= 0) { 
        fprintf(stderr, "Could not find any valid ROP gadget entries.\n");
        return 3;
    }
    // 4. Back track and search for more instructions from each return
    //    instruction to fulfill gadget requirement
    gadget_count = find_gadgets(instructions, return_instructions, return_count, args.gadget_length, gadgets);
    if (gadget_count <= 0) { 
        fprintf(stderr, "Could not find any valid ROP gadget entries of the desired length.\n");
        return 3;
    }
    // 5. Report the gadgets to the user with their entry address
    print_gadgets(gadgets, gadget_count);
    // Clean up and Exit successfully
    free(binary_buffer);
    free(gadgets);
    cs_close(handle);
    cs_free(&instructions, instruction_count);
    cs_free(&return_instructions, return_count);
}