#include "bipan_hash_table.hpp"

#include "logger.hpp"
#include "shared.hpp"

// static unsigned int dumpCount = 0;

BipanHashTable::BipanHashTable() {
  this->maxPrimaryTableSize = 30;
  this->maxChainingListSize = MAX_CHAINING_LIST_SIZE(this->maxPrimaryTableSize);

  for (int i = 0; i < this->maxPrimaryTableSize; i++) {
    this->primaryTable[i].key[0] = '\0';
    this->primaryTable[i].val = 0;
    this->primaryTable[i].next = nullptr;
  }

  this->chainingListIdx = 0;
  for (int i = 0; i < this->maxChainingListSize; i++) {
    this->chainingList[i].key[0] = '\0';
    this->chainingList[i].val = 0;
    this->chainingList[i].next = nullptr;
  }
}

void BipanHashTable::insert(const char* name, int fd) {
  unsigned int key = hash(name);

  // Happy path: slot is empty
  if (primaryTable[key].val == 0 && primaryTable[key].key[0] == '\0') {
    local_strncpy(primaryTable[key].key, name, MAX_KEY_LEN - 1);
    primaryTable[key].key[MAX_KEY_LEN - 1] = '\0';
    primaryTable[key].val = fd;
    return;
  }

  // Slot occupied — check if it's the same key (update)
  if (local_strcmp(primaryTable[key].key, name) == 0) {
    primaryTable[key].val = fd;
    return;
  }

  // Collision — chain it
  if (primaryTable[key].next == nullptr) {
    int scIdx = allocate(name, fd, nullptr);
    primaryTable[key].next = &chainingList[scIdx];
  } else {
    Node* curr = primaryTable[key].next;
    while (curr->next != nullptr) {
      // Update existing entry if same key
      if (local_strcmp(curr->key, name) == 0) {
        curr->val = fd;
        return;
      }
      curr = curr->next;
    }
    // Check tail too
    if (local_strcmp(curr->key, name) == 0) {
      curr->val = fd;
      return;
    }
    int scIdx = allocate(name, fd, nullptr);
    curr->next = &chainingList[scIdx];
  }
}

int BipanHashTable::retrieve(const char* name) {
  unsigned int key = hash(name);

  // Check primary slot
  if (primaryTable[key].key[0] != '\0' &&
      local_strcmp(primaryTable[key].key, name) == 0) {
    return primaryTable[key].val;
  }

  // Walk chain
  Node* curr = primaryTable[key].next;
  while (curr != nullptr) {
    if (local_strcmp(curr->key, name) == 0) {
      return curr->val;
    }
    curr = curr->next;
  }

  return -1;  // miss
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
  // write_to_logcat_async(ANDROID_LOG_DEBUG, TAG, "[*] Destroying Bipan Hash Table");
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
 * Allocates a `Node` on the stack (talking in abstraction:
 * this class's private chaining array).
 *
 * O(1) operation: creating the node with given values,
 * placing it in the array at given index and bumping the latter
 */
int BipanHashTable::allocate(const char* name, int val, Node* next) {
  Node n;
  local_strncpy(n.key, name, MAX_KEY_LEN - 1);
  n.key[MAX_KEY_LEN - 1] = '\0';
  n.val = val;
  n.next = next;
  chainingList[chainingListIdx] = n;
  return chainingListIdx++;
}
