#include "sshgenutils.h"
#include "sshincludes.h"

long ssh_fsize(FILE* file)
{

  long result;
  long pos = ftell(file);
  
  assert(file);
  fseek(file, 0, SEEK_END);
  result = ftell(file);
  fseek(file, pos, SEEK_SET);

  return result;

}


size_t ssh_read_binary_file(const char *filename, char **buf)
{
  FILE *file;
  size_t read_size;
  
  read_size = 0;
  file = fopen(filename, "rb");
  if (file)
  {
    read_size = ssh_fsize(file);
    *buf = (char *)ssh_xmalloc(read_size);
    read_size = fread(*buf, 1, read_size, file);
    fclose(file);
  }

  return read_size;
}

size_t ssh_write_binary_file(const char *filename, size_t file_size, char *buf)
{

  FILE *file;
  size_t write_size = 0;

  file = fopen(filename, "w+b");

  if (file)
    {
      write_size = fwrite(buf, 1, file_size, file);
      fclose(file);
    } 
  
  return write_size;

}
