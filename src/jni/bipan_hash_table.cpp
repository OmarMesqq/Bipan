#include "bipan_hash_table.hpp"

#include "logger.hpp"
#include "shared.hpp"

// static unsigned int dumpCount = 0;

BipanHashTable::BipanHashTable() {
  this->maxPrimaryTableSize = 30;
  this->maxChainingListSize = MAX_CHAINING_LIST_SIZE(this->maxPrimaryTableSize);

  for (int i = 0; i < this->maxPrimaryTableSize; i++) {
    this->primaryTable[i].key = 0;
    this->primaryTable[i].val = 0;
    this->primaryTable[i].next = nullptr;
  }

  this->chainingListIdx = 0;
  for (int i = 0; i < this->maxChainingListSize; i++) {
    this->chainingList[i].key = 0;
    this->chainingList[i].val = 0;
    this->chainingList[i].next = nullptr;
  }
}

void BipanHashTable::insert(const char* name, int fd) {
  unsigned int key = hash(name);
  int internalKey = -1;  // alas, we don't have a perfect hash func

  // Happy O(1) path: hashed name translates to an index whose slot is empty
  if (primaryTable[key].val == 0) {
    primaryTable[key].val = fd;
    internalKey = keyHash(name);
    primaryTable[key].key = internalKey;
    return;
  }

  // Collided...

  int scIdx = -1;  // separate chaining idx

  // O(1): Current slot has no list, start chaining
  if (primaryTable[key].next == nullptr) {
    internalKey = keyHash(name);
    scIdx = allocate(internalKey, fd, nullptr);

    primaryTable[key].next = &chainingList[scIdx];
  } else {
    // O(n): Already chained, traverse the list and append new value at tail
    Node* curr = primaryTable[key].next;
    while (curr->next != nullptr) {
      curr = curr->next;
    }
    internalKey = keyHash(name);

    scIdx = allocate(internalKey, fd, nullptr);
    curr->next = &chainingList[scIdx];
  }
}

int BipanHashTable::retrieve(const char* name) {
  unsigned int key = hash(name);

  // O(1) happy path: single slot, no list to walk through
  if (primaryTable[key].next == nullptr) {
    return primaryTable[key].val;
  }

  int internalKey = -1;
  internalKey = keyHash(name);

  // O(1) too: possibly single slot, but internal key matches filename
  if (primaryTable[key].key == internalKey) {
    return primaryTable[key].val;
  }

  // O(n): walk the chaining to find matching internal key
  Node* curr = &primaryTable[key];
  while (curr != nullptr) {
    internalKey = keyHash(name);
    if (curr->key == internalKey) {
      return curr->val;
    }
    curr = curr->next;
  }
  return -1;
}

void BipanHashTable::dump() {
  for (int i = 0; i < this->maxPrimaryTableSize; i++) {
    if (this->primaryTable[i].val == 0) {
      continue;
    }

    if (this->primaryTable[i].next != nullptr) {
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[%d]: Internal Key: %d | Value: %d | Next: %p", i, this->primaryTable[i].key, this->primaryTable[i].val, (void*)this->primaryTable[i].next);
      // dumpCount++;

      Node* current = this->primaryTable[i].next;
      while (current != nullptr) {
        write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "\t[%d]: Internal Key: %d | Value: %d | Next: %p", i, current->key, current->val, (void*)current->next);
        // dumpCount++;
        current = current->next;
      }
    } else {
      write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[%d]: Internal Key: %d | Value: %d", i, this->primaryTable[i].key, this->primaryTable[i].val);
      // dumpCount++;
    }
  }
  // write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "Dumped %u nodes", dumpCount);
}

BipanHashTable::~BipanHashTable() {
  write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[*] Destroying Bipan Hash Table");
}

unsigned char maxPrimaryTableSize;
unsigned char maxChainingListSize;
Node primaryTable[MAX_TABLE_SIZE];
unsigned char chainingListIdx;
Node chainingList[MAX_CHAINING_LIST_SIZE(MAX_TABLE_SIZE)];

/**
 * Hash function for the primary table:
 * Produces numbers `h` s.t. `h (mod 30)`
 *
 * Over such a small window of possible numbers,
 * this will inevitably collide
 */
unsigned int BipanHashTable::hash(const char* name) {
  unsigned int hash = -1;
  char* p = (char*)name;
  unsigned int sum = 0;
  while (*p) {
    sum += *p - '0';
    p++;
  }
  hash = sum % 30;

  return hash;
}

/**
 * I don't even know if standard hash tables have a secondary hashing algo
 * for the chained nodes indices, but this apparently solved my problem.
 *
 * Once again, outputs numbers modulo CHAINING_TABLE_SIZE
 *
 * Do some random bitwise operations on each digit, add them up
 * and squish everything into remainders < 15. Before that, actually,
 * get remainder by 751, a prime number, because ?
 */
unsigned int BipanHashTable::keyHash(const char* name) {
  unsigned int hash = -1;
  char* p = (char*)name;
  unsigned int sum = 0;
  while (*p) {
    sum += ~((*p - '0') << 1);
    p++;
  }
  // High prime that doesn't produce many collisions (math magic)
  hash = (sum % 751) % 15;

  return hash;
}

/**
 * Allocates a `Node` on the stack (talking in abstraction:
 * this class's private chaining array).
 *
 * O(1) operation: creating the node with given values,
 * placing it in the array at given index and bumping the latter
 */
int BipanHashTable::allocate(int key, int val, Node* next) {
  Node n = {
      .key = key,
      .val = val,
      .next = next};
  chainingList[chainingListIdx] = n;

  return chainingListIdx++;
}
