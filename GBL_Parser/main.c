#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

const char *get_tag_name(uint32_t tag) {
  switch(tag) {
  case 0x03A617EB: return "Header";
  case 0xF40A0AF4: return "Application Info";
  case 0x5EA617EB: return "SE Upgrade";
  case 0xF50909F5: return "Bootloader";
  case 0xFE0101FE: 
  case 0xFD0303FD: return "Program Data";
  case 0xFD0505FD: return "Program LZ4 Compressed Data";
  case 0xFD0707FD: return "Program LZMA Compressed Data";
  case 0xF60808F6: return "Metadata";
  case 0xF30B0BF3: return "Certificate";
  case 0xF70A0AF7: return "Signature";
  case 0xFC0404FC: return "End";
  case 0xFA0606FA: return "Encryption Init Header";
  case 0xF90707F9: return "Encrypted Program Data";
  case 0x04fc92c4: return "UnKnOwN";
  default:
    fprintf(stderr,"Illegal tag 0x%08x\n",tag);
    exit(1);
  }
}

int main (int argc, char *const*argv) {
  FILE *gbl;
  struct stat sb;
  uint8_t *image;
  size_t length, offset;
  assert(2 == argc);
  assert((0 == stat(argv[1],&sb))||"file unstatable?");
  length = sb.st_size;
  assert((image = malloc(length)));
  assert((gbl = fopen(argv[1],"r")));
  assert(length == fread(image,1,length,gbl));
  fclose(gbl);
  offset = 0;
  do {
    uint32_t tag;
    uint32_t length;
    memcpy(&tag,&image[offset],4);
    memcpy(&length,&image[offset+4],4);
    offset += 8 + length;
    printf("Tag: %08x (%s), Length: %u\n",tag,get_tag_name(tag), length);
  } while(offset < length);
  return 0;
}
