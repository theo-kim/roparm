#include "roparm.h"

// Parse arguments, return -1 is error, else return 0 if the filename
//      was included and 1 if to expect the file from stdin
int parse_arguments(int argc, char **argv, args_t *args) {
    int next_argument_enum = ENUM_ARGUMENT;
    // Initialize arguments
    args->filename = NULL;
    args->gadget_length = -1;
    args->start_address = 0x80001000;
    args->thumb_mode = 1;
    // No instances that only one argument works
    if (argc == 1) {
        report_error(ERROR_INCORRECT_ARGS);
        return -1;
    }
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] != '-') {
            // It is a value
            switch (next_argument_enum) {
                case ENUM_FILENAME :
                    args->filename = argv[i];
                    break;
                case ENUM_GADGET_LEN :
                    args->gadget_length = atoi(argv[i]);
                    if (args->gadget_length == 0 && argv[i][0] != '0') report_error_with_insert(ERROR_UNKNOWN_NUMBER, argv[i]);
                    else break;
                    return -1;
                case ENUM_MODE :
                    if (strncmp(argv[i], "thumb", 5) == 0 || strncmp(argv[i], "THUMB", 5) == 0) args->thumb_mode = 1;
                    else if (strncmp(argv[i], "arm", 3) == 0 || strncmp(argv[i], "ARM", 3) == 0) args->thumb_mode = 0;
                    else {
                        report_error_with_insert(ERROR_UNKNOWN_MODE, argv[i]);
                        return -1;
                    }
                    break;
                default :
                    report_error(ERROR_VALUE_NOT_NEED);
                    return -1;
            }
            next_argument_enum = ENUM_ARGUMENT;
            continue;
        }
        if (next_argument_enum != ENUM_ARGUMENT) {
            // Expecting a value but an argument was provided
            report_error(ERROR_EXPECT_VALUE);
            return -1;
        }
        // It is an argument
        switch (argv[i][1]) {
            case HELP_FLAG :
                printf(HELP_MESSAGE);
                return -1; // help
            case FILE_FLAG :
                next_argument_enum = ENUM_FILENAME;
                break; // define file name
            case GADGET_LEN_FLAG :
                next_argument_enum = ENUM_GADGET_LEN;
                break; // define gadget length
            case MODE_FLAG :
                next_argument_enum = ENUM_MODE;
                break; // define elf arm mode
            default :
                report_error_with_insert(ERROR_UNKNOWN_FLAG, &argv[i][1]);
                return -1;
        }
    }
    if (args->gadget_length == -1) {
        report_error(ERROR_MISSING_LEN);
        return -1;
    }
    if (args->gadget_length == 0) {
        report_error(ERROR_NON_ZERO_LEN);
        return -1;
    }
    if (args->filename == NULL) {
        return ENUM_LOAD_STDIN;
    }
    return ENUM_LOAD_FILE;
}

int load_binary(FILE *fp, uint8_t **buffer) {
    int content_length = 0;
    int read_length = 0;
    int buffer_size = BUFFER_SIZE;
    // Allocate the buffer
    *buffer = malloc(buffer_size);
    // Read the file into the buffer
    while ((read_length = fread((*buffer) + content_length, 1, BUFFER_SIZE, fp)) > 0) {
        // If more to read, update total length
        content_length += read_length;
        // reallocate more size to the buffer
        *buffer = realloc(*buffer, buffer_size += BUFFER_SIZE);
    }
    // Check if something was read
    if (content_length == 0) {
        report_error(ERROR_EMPTY_FILE);
        return -1;
    }
    return content_length;
}

// Load the binary into the buffer and return the length of the buffer
int load_binary_from_file(char *filename, uint8_t **buffer) {
    // Open file
    FILE *f = fopen(filename, "rb");
    if (f == NULL) {
        report_error_with_insert(ERROR_UNKNOWN_FILE, filename);
        return -1;
    }
    int binary_length = load_binary(f, buffer);
    // close out f
    fclose(f);
    return binary_length;
}

int load_binary_from_stdin(uint8_t **buffer) {
    int binary_length = load_binary(stdin, buffer);
    return binary_length;
}