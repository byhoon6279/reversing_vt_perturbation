# PEobfuscator
PE Obfuscator

- [x] Overlay Append (Padding)
  - Appends benign contents at the end of a binary

- [x] Perturb Header Fields
  - [x] Alters section names
  - [x] breaking the checksum
  - [x] and altering debug information

- [x] Filling Slack Space
  - Modifies the bytecodes in code cave
     
- [x] Modifying DOS Header and Stub
  - Modifies some bytes in the DOS Header

- [ ] Extend the DOS Header
  - Injects content before the actual header of the program
  
- [x] Content shifting
  - Creates additional space before the beginning of a section, by shifting the content forward, and injects adverse
    
- [x] Import Function Injection
  - Adds an appropriate entry to the Import Address Table
  
- [x] Section add
  - Adds a new section with benign contents.
  
- [x] Section append
  - Appends random bytes to the unused space between sections

- [x] Packing
  - Packing Packs a file with various tools or custom tool
  
- [x] Change entry point
  - Sets the entry-point to a new executable section that jumps back to the original code
  
- [ ] Dropper
  - Stores the code as a resource of another binary, which is then loaded at runtime
  
- [ ] Code Randomization
  - Replace instruction sequence with semantically equivalent one
  - [x] xor -> sub
  - [x] test -> or
  - [ ] mov -> push
  - [ ] nop -> jmp

- [x] entry point extend
  - Section offset, RVA 값 변경
  
- [ ] nop insertion
  - 중간중간 nop 추가
  
- [x]  jmp/jmp back to other address
  - Overlay에 추가한 address에 jump하고 기존 code로 다시 jump
