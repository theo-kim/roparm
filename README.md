# ARM ROP Gadget Finder
This is a ROP Gadget Finder utility for the ARM architecture. 

## Existing Distributions:
[GitHub releases](https://github.com/theo-kim/roparm/releases) contains two tested binaries, one for macOS (tested on 10.15.4) and one for Ubuntu Linux (tested on 18.04). They are dynamically linked, so make sure your have Capstone engine installed to your PATH visible library directory.

## Building from Source
You can also build the project from source. **Windows is not supported.** To do so, just run `make` in the project root. For macOS and Ubuntu, a compiled version of capstone comes with the project. Alternatively, if you have Capstone Engine installed to a PATH visible library directory, the Makefile will use that too.

## Usage
The purpose of ROPARM is to find and report Return Object Programming Gadgets from a ELF binary to the user to be used in penetration testing of embedded binaries. Right now, it ONLY works on ELF binaries, not raw assembled ARM code. It ONLY works on ARM (ARM or THUMB).

The basic usage is as follows:
```
$ roparm -l <gadget length> [<args> <values>]
```

### Acceptable arguments:
- `-m` : force a mode (either THUMB or ARM) to search for gadgets, otherwise, by default, the program will find both
- `-l` : gadget length
- `-f` : ARM ELF to disassemble (by default it reads the ELF from STDIN)
- `-h` : display help message

### Sample Output:
```
Found 871 instructions
Found 12 return-like instructions
Found 12 gadgets
[THUMB] 0x8572: b.w #0x84b0; bx lr; 
[THUMB] 0x858e: strb r2, [r3]; bx lr; 
[THUMB] 0x85ac: blx r3; pop {r3, pc}; 
[THUMB] 0x8a7c: mov.w r0, #0; mov pc, r2; 
[THUMB] 0x8c8e: rsbmi r0, r0, #0; bx lr; 
[THUMB] 0x8c98: rsbmi r0, r0, #0; bx lr; 
[THUMB] 0x8ca6: orreq r0, r0, #1; bx lr; 
[THUMB] 0x8cbe: rsbmi r0, r0, #0; bx lr; 
[THUMB] 0x8ce8: sub.w r1, r1, r3; bx lr; 
[THUMB] 0x8cf6: blx #0x84d8; pop {r1, pc}; 
[THUMB] 0x8d2e: blo #0x8d1e; pop.w {r3, r4, r5, r6, r7, r8, sb, pc}; 
[THUMB] 0x8d3a: movs r0, r0; bx lr; 
```

## Acknowledgement
This project utilizes the Capstone Engine compiled for C. Done under the guidance of Stephen Ridley, for his course **Intro to Embedded Binary Exploitation** at New York University, Tandon School of Engineering, Spring 2020.