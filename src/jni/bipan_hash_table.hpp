#ifndef BIPAN_HASH_TABLE_HPP
#define BIPAN_HASH_TABLE_HPP

#include "logger.hpp"
#define TAG "BipanHashTable"

/**
 * For now, this size should suffice as we don't have many spoofed filenames.
 * Before bumping this, please, check the type of the private member `tableSize`.
 *
 * Currently, the table fits in an `unsigned char`
 */
#define MAX_TABLE_SIZE 40

typedef struct _node {
  unsigned short key;  // "hashed" filename
  int val;             // its associated file descriptor
} Node;

/**
 * Stack-only, AS-safe safe "hash table".
 *
 * This actually runs in O(n^2) (worst case).
 *
 * The `pseudoHash` function reads each char of the string
 * and inserting/retrieving involves reading the stack array
 * entries(at worst, `MAX_TABLE_SIZE`) iterations.
 *
 * Still, since the filenames are cached for the lifetime of the app
 * and most apps won't hit them all, I guess it should be fast enough.
 * Afterall, it's just pointer and basic arithmetic being done here.
 *
 *      - "It ain't much, but it's honest work"
 */
class BipanHashTable {
 public:
  BipanHashTable();
  bool insert(const char* name, int fd);
  int retrieve(const char* name);
  void logStats();
  ~BipanHashTable();

 private:
  unsigned char tableSize;
  Node table[MAX_TABLE_SIZE];
  unsigned int pseudoHash(const char* name);
};

#endif  // BIPAN_HASH_TABLE_HPP