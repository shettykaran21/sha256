// Author: Edward Eldridge
// Program: SHA-256 Algorithm implentation in C
// Resources: https://github.com/EddieEldridge/SHA256-in-C/blob/master/README.md
// Section Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define byteSwap32(x)                                                \
  (((x) >> 24) | (((x)&0x00FF0000) >> 8) | (((x)&0x0000FF00) << 8) | \
   ((x) << 24))
#define byteSwap64(x)                                                        \
  ((((x) >> 56) & 0x00000000000000FF) | (((x) >> 40) & 0x000000000000FF00) | \
   (((x) >> 24) & 0x0000000000FF0000) | (((x) >> 8) & 0x00000000FF000000) |  \
   (((x) << 8) & 0x000000FF00000000) | (((x) << 24) & 0x0000FF0000000000) |  \
   (((x) << 40) & 0x00FF000000000000) | (((x) << 56) & 0xFF00000000000000))

// Define a union for easy reference
// Union represents a message block
union messageBlock {
  __uint8_t e[64];
  __uint32_t t[16];
  __uint64_t s[8];
};

// ENUM to control state of the program
enum status { READ, PAD0, PAD1, FINISH };

// Tell our preprocessor to create a variable MAXCHAR with value of 100000
#define MAXCHAR 100000

int calcFileSize(FILE *file);
void endianCheckPrint();
_Bool endianCheck();
void appendToFile(char fileName[], char fileContents[]);
void appendToFileHash(char fileName[], __uint32_t fileContent);
int fillMessageBlock();
char *calculateHash(FILE *file);
int nextMessageBlock(FILE *file, union messageBlock *msgBlock,
                     enum status *state, __uint64_t *numBits);
void getOutputContent(FILE *file);
void storeInHash(FILE *file);
int hashIndex(char *name);

struct HashValue {
  char *name;
  char *hash;
};

void initName(struct HashValue *s, char name[]) { s->name = name; }
void initHash(struct HashValue *s, char hash[]) { s->hash = hash; }

struct HashValue hashes[1000];
int totalHashes = 0;

__uint32_t sig0(__uint32_t x);
__uint32_t sig1(__uint32_t x);

__uint32_t rotr(__uint32_t n, __uint16_t x);
__uint32_t shr(__uint32_t n, __uint16_t x);

__uint32_t SIG0(__uint32_t x);
__uint32_t SIG1(__uint32_t x);

__uint32_t Ch(__uint32_t x, __uint32_t y, __uint32_t z);
__uint32_t Maj(__uint32_t x, __uint32_t y, __uint32_t z);

int main(int argc, char *argv[]) {
  FILE *file;
  char *fileName;
  int argumentCount = argc;

  printf("\n======== SHA256 - HASHING ALGORITHM ========");

  if (argumentCount == 0) {
    printf("Please supply a file to hash as command line arguments.");
    exit;
  } else if (argumentCount >= 1) {
    printf("\n Correct arguments. Attemping to read file.. \n");

    fileName = argv[1];

    file = fopen(fileName, "r");

    if (file == NULL) {
      printf("\n Could not open file %s\n", fileName);
    } else {
      char inputFileContents[MAXCHAR];
      char *hashValue;

      printf("\n File ok, executing functions.. \n");
      endianCheckPrint();

      storeInHash(fopen("output.txt", "r"));

      fscanf(file, "%s", inputFileContents);

      hashValue = calculateHash(file);

      if (!hashIndex(inputFileContents)) {
        // Append to file
        appendToFile("output.txt", inputFileContents);
        appendToFile("output.txt", " ");
        appendToFile("output.txt", hashValue);
        appendToFile("output.txt", "\n");
      } else {
        // Check if it matching current hash
        int index = hashIndex(inputFileContents);

        if (strcmp(hashValue, hashes[index].hash) == 0) {
          printf("\n");
          printf(" There is no virus in the system. The file is secured\n");
        } else {
          printf("\n");
          printf(
              " There is virus attached to this file. The hash value has "
              "been "
              "changed\n");
        }
      }
    }
  } else {
    printf("Invalid arguments, please recheck your spelling.");
    exit;
  }

  return 0;
}

int hashIndex(char *name) {
  for (int i = 0; i < totalHashes; ++i) {
    if (strcmp(name, hashes[i].name) == 0) {
      return i;
    }
  }
  return 0;
}

char *calculateHash(FILE *file) {
  union messageBlock msgBlock;

  __uint64_t numBits = 0;

  enum status state = READ;

  printf("\n Starting SHA256 algorithm....\n");

  __uint32_t K[] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  __uint32_t W[64];

  __uint32_t a, b, c, d, e, f, g, h;

  __uint32_t T1;
  __uint32_t T2;

  __uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  int j;
  int o;

  printf("\n Initalized variables... Entering loops\n");

  while (fillMessageBlock(file, &msgBlock, &state, &numBits)) {
    for (j = 0; j < 16; j++) {
      if (endianCheck() == true) {
        W[j] = msgBlock.t[j];
      } else {
        W[j] = byteSwap32(msgBlock.t[j]);
      }
    }

    for (j = 16; j < 64; j++) {
      W[j] = sig1(W[j - 2]) + W[j - 7] + sig0(W[j - 15]) + W[j - 16];
    }

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    for (j = 0; j < 64; j++) {
      T1 = h + SIG1(e) + Ch(e, f, g) + K[j] + W[j];
      T2 = SIG0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
  }

  char hexSwapArray[9];

  char *hexFullArray;
  hexFullArray = (char *)malloc(sizeof(char) * 65);
  hexFullArray[0] = '\0';

  for (int i = 0; i < 8; ++i) {
    sprintf(hexSwapArray, "%x", H[i]);
    strcat(hexFullArray, hexSwapArray);
  }

  fclose(file);

  return hexFullArray;
}

void appendToFile(char fileName[], char fileContents[]) {
  FILE *fptr;
  fptr = fopen(fileName, "a+");
  fprintf(fptr, "%s", fileContents);
  fclose(fptr);
}

void storeInHash(FILE *file) {
  char fileContents[20][MAXCHAR];
  long fileSize;

  if (file == NULL) {
    printf("\n Could not open file");
  } else {
    int i = 0;
    while (fscanf(file, "%s", fileContents[i]) != EOF) {
      fileContents[i][strlen(fileContents[i])] = '\0';
      i++;
    }

    fclose(file);

    int totalStrings = i;
    int j = 0;
    for (i = 0; i < totalStrings; ++i) {
      if (!(i & 1)) {
        initName(&hashes[j], fileContents[i]);
      } else {
        initHash(&hashes[j], fileContents[i]);
        j++;
      }
    }

    totalHashes = j;

    return;
  }
}

int calcFileSize(FILE *file) {
  int prev = ftell(file);
  fseek(file, 0L, SEEK_END);
  int size = ftell(file);
  fseek(file, prev, SEEK_SET);
  return size;
}

void endianCheckPrint() {
  int num = 1;
  if (*(char *)&num == 1) {
    printf("\n Your system is Little-Endian!\n");
  } else {
    printf("Your system is Big-Endian!\n");
  }
}

_Bool endianCheck() {
  int num = 1;
  if (*(char *)&num == 1) {
    return false;
  } else {
    return true;
  }
}

int fillMessageBlock(FILE *file, union messageBlock *msgBlock,
                     enum status *state, __uint64_t *numBits) {
  __uint64_t numBytes;
  int i;

  if (*state == FINISH) {
    printf("\n State = FINISH.\n");
    return 0;
  }

  if (*state == PAD0 || *state == PAD1) {
    printf("\n State = PAD0 or PAD1.\n");

    for (i = 0; i < 56; i++) {
      msgBlock->e[i] = 0x00;
    }

    msgBlock->s[7] = byteSwap64(*numBits);

    *state = FINISH;

    if (*state == PAD1) {
      msgBlock->e[0] = 0x01;
    }

    return 1;
  }

  numBytes = fread(msgBlock->e, 1, 64, file);

  *numBits = *numBits + (numBytes * 8);

  if (numBytes < 56) {
    msgBlock->e[numBytes] = 0x80;

    while (numBytes < 56) {
      numBytes = numBytes + 1;

      msgBlock->e[numBytes] = 0x00;
    }

    msgBlock->s[7] = byteSwap64(*numBits);

    *state = FINISH;
  } else if (numBytes < 64) {
    *state = PAD0;

    msgBlock->e[numBytes] = 0x80;

    while (numBytes < 64) {
      numBytes = numBytes + 1;
      msgBlock->e[numBytes] = 0x00;
    }
  } else if (feof(file)) {
    *state = PAD1;
  }
  return 1;
}

__uint32_t sig0(__uint32_t x) {
  return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3));
};

__uint32_t sig1(__uint32_t x) {
  return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10));
};

__uint32_t rotr(__uint32_t x, __uint16_t a) {
  return (x >> a) | (x << (32 - a));
};

__uint32_t shr(__uint32_t x, __uint16_t b) { return (x >> b); };

__uint32_t SIG0(__uint32_t x) {
  return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22));
};

__uint32_t SIG1(__uint32_t x) {
  return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25));
};

__uint32_t Ch(__uint32_t x, __uint32_t y, __uint32_t z) {
  return ((x & y) ^ (~(x)&z));
};

__uint32_t Maj(__uint32_t x, __uint32_t y, __uint32_t z) {
  return ((x & y) ^ (x & z) ^ (y & z));
};
