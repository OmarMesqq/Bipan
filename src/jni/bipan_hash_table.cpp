#include "bipan_hash_table.hpp"

BipanHashTable::BipanHashTable() {
  this->tableSize = MAX_TABLE_SIZE;

  for (int i = 0; i < this->tableSize; i++) {
    this->table[i].key = 0;
    this->table[i].val = -1;
  }
}

/**
 * @param name absolute path to be cached (null-terminated C-string)
 * @param fd already open file descriptor relative to `name`. This shouldn't be closed
 *
 *
 * @returns
 * `true` on successful insertion (file wasn't cached)
 *
 * `false` on null pointers, attempted reinsertions or full table
 */
bool BipanHashTable::insert(const char* name, int fd) {
  if (name == nullptr) {
    return false;
  }
  unsigned int key = pseudoHash(name);

  for (int i = 0; i < this->tableSize; i++) {
    // Reject reinsertions
    if (table[i].key == key && table[i].val != -1) {
      return false;
    }

    // Found empty slot
    if (table[i].key == 0) {
      table[i].key = (unsigned short)key;  // guess this cast is acceptable for now
      table[i].val = fd;
      return true;
    }
  }
  // Table is full!
  return false;
}

/**
 * @param name absolute path (null-terminated C-string) to which you want a relative FD
 *
 * @returns
 * `-1` on null pointers or `name` not in the table
 * valid fd (non-negative integer) otherwise
 */
int BipanHashTable::retrieve(const char* name) {
  if (name == nullptr) {
    return -1;
  }
  unsigned int key = pseudoHash(name);

  for (int i = 0; i < this->tableSize; i++) {
    if (table[i].key == key) {
      return table[i].val;
    }
  }
  return -1;  // miss
}

/**
 * Writes the table's occupied buckets and its load factor to `logcat`
 */
void BipanHashTable::logStats() {
  unsigned char filledSlots = 0;

  for (unsigned char i = 0; i < this->tableSize; i++) {
    if (table[i].key == 0) {
      continue;
    }
    filledSlots++;
  }
  unsigned int loadFactor = filledSlots / this->tableSize;
  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[D] Occupied slots: %u | Load factor: %u", filledSlots, loadFactor);
}

BipanHashTable::~BipanHashTable() {
  // write_to_logcat_async(ANDROID_LOG_WARN, TAG, "[*] Destroying Bipan Hash Table");
}

unsigned char tableSize;
Node table[MAX_TABLE_SIZE];

/**
 * Calling this a hash function would be weird. Kinda like
 * calling someone tall if they're wearing high heels.
 *
 * Simply get the decimal value of each char in the string
 * and add it all together to create the key. What really
 * keeps this fragile implementation working is the
 * `shouldCache` function which prevents undesired
 * pathnames from being inserted in the table.
 */
unsigned int BipanHashTable::pseudoHash(const char* name) {
  char* p = (char*)name;
  unsigned int sum = 0;
  while (*p) {
    sum += *p - '0';
    p++;
  }
  return sum;
}
