section .text
global  myNtAllocateVirtualMemory 
myNtAllocateVirtualMemory :
  mov r10, rcx
  mov eax, 18h ; syscall number for NtAllocateVirtualMemory
  syscall
  ret

global myNtWriteVirtualMemory
myNtWriteVirtualMemory:
  mov r10, rcx         ; Preserve o valor de RCX
  mov eax, 0x3A        ; Número da syscall para NtWriteVirtualMemory
  syscall              ; Executa a chamada de sistema
  ret                  ; Retorna da função
