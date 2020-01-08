#include <stddef.h>
#include <stdio.h>

struct list_head {
  struct list_head* next;
  struct list_head* prev;
};

struct something {
  int nr;
  struct list_head list;
};

//#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

void print_nr(struct list_head* list) {
  struct something* s = container_of(list, struct something, list);
  printf("print_nr: %d\n", s->nr);
}

int main(int argc, char** argv) {
  struct list_head s_list = { NULL, NULL};
  struct something s = { 18, s_list};

  print_nr(&s.list);
  //struct something* s2 = container_of(&s.list, struct something, list);

  return 0;
}
