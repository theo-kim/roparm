#include "stdio.h"
#include "capstone/capstone.h"

#include "roparm.h"

int main(int argc, char **argv) {
    args_t args;
    gadget_t *gadgets;
    int operation_mode, binary_buffer_len, instruction_count, return_count,
        gadget_count, text_section_len, cs_mode;
    uint8_t *binary_buffer;
    elf_t elf;
    csh handle;
    cs_insn *instructions, **return_instructions;
    cs_err err;

    // 1. Check for command line arguments and validate
    if ((operation_mode = parse_arguments(argc, argv, &args)) < 0) {
        return 1;
    }
    // 1a. (if file is not provided by argument) Load file from stdin
    if (operation_mode == ENUM_LOAD_FILE) {
        binary_buffer_len = load_binary_from_file(args.filename, &binary_buffer);
    }
    // 1b. (if file is provided by argument) Open file and load into buffer
    else {
        binary_buffer_len = load_binary_from_stdin(&binary_buffer);
    }
    if (binary_buffer_len <= 0) {
        return -1;
    }
    // 2. Disassemble the provided binary
    // Parse ELF
    text_section_len = extract_text(binary_buffer, binary_buffer_len, &elf);
    if (text_section_len <= 0) {
		return 2;
    }
    // Initialize Capstone Engine
    if (elf.is_thumb == 1) {
        cs_mode = CS_MODE_THUMB;
    }
    else {
        cs_mode = CS_MODE_ARM;
    }
    if (elf.little_endian == 1) {
        cs_mode += CS_MODE_LITTLE_ENDIAN;
    }
    else {
        cs_mode += CS_MODE_BIG_ENDIAN;
    }
    if ((err = cs_open(CS_ARCH_ARM, cs_mode, &handle))) {
        fprintf(stderr, "Failed to initialize Capstone Engine with error: %u\n", err);
		return 2;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON); // turn on skip data mode to ignore faulty functions
    // Disassemble
    instruction_count = cs_disasm(handle, elf.bytes, text_section_len, elf.entry_address, 0, &instructions);
    if (instruction_count <= 0) {
        fprintf(stderr, "Could not disassemble supplied binary. Make sure it is an ARM binary (not THUMB): %d\n", instruction_count);
        return 3;
    }
    // 3. Scan the file and search for return statements
    //    in ARM, there is not RET instruction, so we need to look for any 
    //    instruction that writes to the PC register.
    return_count = find_return(handle, instructions, instruction_count, &return_instructions);
    if (return_count <= 0) { 
        fprintf(stderr, "Could not find any valid ROP gadget entries.\n");
        return 4;
    }
    // 4. Back track and search for more instructions from each return
    //    instruction to fulfill gadget requirement
    gadget_count = find_gadgets(return_instructions, return_count, args.gadget_length, &gadgets);
    if (gadget_count <= 0) { 
        fprintf(stderr, "Could not find any valid ROP gadget entries of the desired length.\n");
        return 5;
    }
    // 5. Report the gadgets to the user with their entry address
    print_gadgets(gadgets, gadget_count);
    // Clean up and Exit successfully
    cs_free(instructions, instruction_count);
    cs_close(&handle);
    free(binary_buffer);
    free(return_instructions);
    free(gadgets);

    return 0;
}