#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
// dummy comment 
int main(void) {
  size_t pagesize = getpagesize();
  printf("System page size: %zu bytes\n", pagesize);

  size_t sc_pagesize = (size_t)sysconf(_SC_PAGESIZE);
  printf("_SC_PAGESIZE: %zu bytes\n", sc_pagesize);
 
  char* mem_area = mmap(NULL, // let the kernel choose the address
                        pagesize, // length of the mapping
                        PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE,
                        -1, // since this is an anonymous mapping fd is ignored
                        0); // likewise the offset should be zero in this case.

  if (mem_area == MAP_FAILED) {
    perror("Could not mmap");
    return 1;
  }
 
  strcpy(mem_area, "Something...");

  mprotect(mem_area, pagesize, PROT_EXEC);
 
  printf("mem_area address: %p\n", &mem_area);
  printf("mem_area content: %s\n", mem_area);
 
  int unmap_result = munmap(mem_area, pagesize);
  if (unmap_result != 0 ) {
    perror("Could not munmap");
    return 1;
  }
  return 0;
}
