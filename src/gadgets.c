#include "roparm.h"
#include "elf.h"

// Error reporting
void report_error(const char *msg) {
    fprintf(stderr, CONSOLE_COLOR(ANSI_COLOR_RED, "%s\n"), msg);
}

void report_error_with_insert(const char *msg, char *insert) {
    fprintf(stderr, CONSOLE_COLOR(ANSI_COLOR_RED, "%s: %s\n"), msg, insert);
}

int extract_text(uint8_t *binary_buffer, size_t buffer_len, elf_t *text_section) {
    int is32bit = 0;
    int sheader_offset = 0, sheader_count = 0, sheader_size = 0;
    Elf32_Ehdr *header;
    // check if its really an elf file with MAGIC BYTES
    if (binary_buffer[0] != 0x7F || binary_buffer[1] != 'E' || binary_buffer[2] != 'L' || binary_buffer[3] != 'F') {
        report_error(ERROR_NOT_ELF);
        return -1;
    }
    // Check architecture (32 or 64)
    if (binary_buffer[4] == 0x01) {
        is32bit = 1;
    }
    if (is32bit) {
        header = (Elf32_Ehdr *)binary_buffer;
        // Check File Type
        if (header->e_type != ET_DYN && header->e_type != ET_EXEC) {
            report_error(ERROR_NOT_EXEC_DYN);
            return -1;
        }
        else {
            text_section->type = header->e_type;
        }
        // Check architecture
        if (header->e_machine != EM_ARM) {
            report_error(ERROR_NOT_ARM);
            return -1;
        }
        // Check entry
        if ((header->e_entry & 0b1) == 1) {
            text_section->is_thumb = 1;
        }
        else {
            text_section->is_thumb = 0;
        }
        // Check endianness
        if (header->e_ident[EI_DATA] == ELFDATA2LSB) {
            // little endian
            text_section->little_endian = 1;
        }
        else {
            text_section->little_endian = 0 ;
        }
        // Get section table information
        sheader_offset = header->e_shoff;
        sheader_count = header->e_shnum;
        sheader_size = header->e_shentsize;
        // Get section symbol table
        int indx = header->e_shstrndx;
        Elf32_Shdr *shstr_header = (void *)binary_buffer + sheader_offset + (indx * sheader_size);
        char * symbol_table = (void *)binary_buffer + shstr_header->sh_offset;

        for (size_t i = 0; i < sheader_count; ++i) {
            Elf32_Shdr *section_header = (void *)binary_buffer + sheader_offset + (i * sheader_size);
            if (section_header->sh_type == SHT_PROGBITS) {
                char *section_name = symbol_table + section_header->sh_name;
                printf("%s: %d\n", section_name, section_header->sh_type);
                if (strncmp(section_name, ".text", 5) == 0) {
                    text_section->size = section_header->sh_size;
                    text_section->bytes = binary_buffer + section_header->sh_offset;
                    text_section->entry_address = section_header->sh_addr;
                }
            }
        }
        return text_section->size;
    }
    report_error(ERROR_64BIT);
    return -1;
}

// Find return instructions, return number of instructions found
int find_return(csh handle, cs_insn *capstone_instructions, int instruction_count, cs_insn ***return_instructions) {
    int return_count = 0, return_capacity = 1;
    *return_instructions = (cs_insn **)malloc(sizeof(cs_insn *) * return_capacity);
    printf(CONSOLE_COLOR(ANSI_COLOR_GREEN, "Found %d instructions\n"), instruction_count);
    for (size_t i = 0; i < instruction_count; ++i) {
        cs_insn *instruction = &capstone_instructions[i];
        cs_arm *arm = &(instruction->detail->arm);
        if (instruction->id == 0x00) // ID is none so it is an unknown instruction
            continue;
        // printf("0x%" PRIx64 ":\t%s\t%s\n", instruction.address, instruction.mnemonic, instruction.op_str);
        for (int j = 0; j < arm->op_count; ++j) {
            cs_arm_op *op = &(arm->operands[j]);
            if ((op->type == ARM_OP_REG && op->access == CS_AC_WRITE && op->reg == ARM_REG_PC) || (instruction->id == ARM_INS_BX && op->reg == ARM_REG_LR)) {
                // Found an instruction which writes to the instruction pointer in the destination
                if (return_count++ >= return_capacity) {
                    return_capacity *= 2;
                    *return_instructions = (cs_insn **)realloc(*return_instructions, sizeof(cs_insn *) * return_capacity);
                }
                (*return_instructions)[return_count - 1] = instruction;
                break;
            }
        }
    }
    return return_count;
}

int check_gadget(cs_insn *startpoint, int gadget_length, cs_insn **gadget_start) {
    for (int i = 0; i < gadget_length; ++i) {
        cs_insn *insn = startpoint - i;
        if (insn->id == 0x00) {
            // Not a valid instruction, therefore cannot be used for gadget
            return i;        
        }
        *gadget_start = insn;
    }
    return gadget_length;
}

// Find gadgets based on the instructions found in the previous step,
int find_gadgets(cs_insn **return_instructions, int instruction_n, int gadget_length, gadget_t **gadgets, int mode) {
    int num_gadgets = 0;
    // Malloc array    
    *gadgets = (gadget_t *)malloc(instruction_n * sizeof(gadgets));
    // Go through each return instruction and count backwards
    printf(CONSOLE_COLOR(ANSI_COLOR_BLUE, "Found %d return-like instructions\n"), instruction_n);
    for (int i = 0; i < instruction_n; ++i) {
        cs_insn *insn = return_instructions[i];
        cs_insn *gadget_start = NULL;
        int gadget_len = 0;
        if ((gadget_len = check_gadget(insn, gadget_length, &gadget_start)) == 0) {
            continue;
        }
        (*gadgets)[i].gadget_len = gadget_len;
        (*gadgets)[i].start = gadget_start;
        (*gadgets)[i].is_thumb = 1;
        ++num_gadgets;
        // printf(CONSOLE_COLOR(ANSI_COLOR_MAGENTA, "0x%" PRIx64) ":\t"CONSOLE_COLOR(ANSI_COLOR_YELLOW, "%s")"\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    return num_gadgets;
}

// Print gadgets onto STDOUT
void print_gadgets(gadget_t *gadgets, int number_gadgets) {
    printf("Found %d gadgets\n", number_gadgets);
    for (int i = 0; i < number_gadgets; ++i) {
        cs_insn *insn = gadgets[i].start;
        if (gadgets[i].is_thumb == 1) {
            printf("[" CONSOLE_COLOR(ANSI_COLOR_GREEN, "THUMB")"]\t");
        }
        else {
            printf("[" CONSOLE_COLOR(ANSI_COLOR_GREEN, "ARM")"]\t");
        }
        printf(CONSOLE_COLOR(ANSI_COLOR_MAGENTA, "0x%" PRIx64)": ", insn->address);
        for (int j = 0; j < gadgets[j].gadget_len; ++j  ) {
            cs_insn *insn = gadgets[i].start + j;
            printf(CONSOLE_COLOR(ANSI_COLOR_YELLOW, "%s")" %s; ", insn->mnemonic, insn->op_str);
        }
        printf("\n");
        // printf(":\t"CONSOLE_COLOR(ANSI_COLOR_YELLOW, "%s")"\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    }
    return;
}