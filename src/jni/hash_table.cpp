#include <stdio.h>

#include <cassert>
#include <map>
#include <string>

// Should be 16 bytes
typedef struct _node {
  int key;  // for differentiating nodes on chaining
  int val;  // the actual FD
  struct _node* next; // for chaining, if necessary
} Node;

static unsigned int dumpCount = 0;

#define MAX_TABLE_SIZE 30
// putting to half for simplicity, not many files to spoof
#define MAX_CHAINING_LIST_SIZE(x) MAX_TABLE_SIZE / 2

/**
 * Stack-only, AS-safe safe hash table with separate chaining.
 * This *will* leave many empty slots in the primary table ,
 * but I'd have to research (copy?) a better hashing algo.
 *
 * Still, I wanted to try this on my own and for < 30
 * filenames I was getting at most 3 nodes on the
 * linked lists. This should be quite fast to traverse
 * even if we waste some stack space with empty slots.
 *
 *      - "It ain't much, but it's honest work"
 */
class BipanHashTable {
 public:
  BipanHashTable() {
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

  void insert(const char* name, int fd) {
    unsigned int key = hash(name);
    int internalKey = -1; // alas, we don't have a perfect hash func

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

  int retrieve(const char* name) {
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

  void dump() {
    printf("\n");
    for (int i = 0; i < this->maxPrimaryTableSize; i++) {
      if (this->primaryTable[i].val == 0) {
        continue;
      }

      if (this->primaryTable[i].next != nullptr) {
        printf("[%d]: Internal Key: %d | Value: %d | Next: %p\n", i, this->primaryTable[i].key, this->primaryTable[i].val, (void*)this->primaryTable[i].next);
        dumpCount++;

        Node* current = this->primaryTable[i].next;
        while (current != nullptr) {
          printf("\t[%d]: Internal Key: %d | Value: %d | Next: %p\n", i, current->key, current->val, (void*)current->next);
          dumpCount++;
          current = current->next;
        }
      } else {
        printf("[%d]: Internal Key: %d | Value: %d\n", i, this->primaryTable[i].key, this->primaryTable[i].val);
        dumpCount++;
      }
    }
    printf("Dumped %u nodes\n", dumpCount);
  }

  ~BipanHashTable() {
    // fprintf(stdout, "Destroying Bipan Hash Table\n");
  }

 private:
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
  unsigned int hash(const char* name) {
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
  unsigned int keyHash(const char* name) {
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
  int allocate(int key, int val, Node* next) {
    Node n = {
        .key = key,
        .val = val,
        .next = next};
    chainingList[chainingListIdx] = n;

    return chainingListIdx++;
  }
};

int main() {
  BipanHashTable bht;
  printf("sizeof(Node): %zu bytes\n", sizeof(Node));

  std::map<std::string, int> primaryTable = {
      {"/proc/meminfo", 137},
      {"/proc/cpuinfo", 911},
      {"/etc/hosts", 37},
      {"/system/etc/hosts", 603},
      {"/sys/devices/system/cpu/kernel_max", 487},
      {"/sys/devices/system/cpu/possible", 825},
      {"/sys/devices/system/cpu/online", 261},
      {"/sys/devices/system/cpu/present", 719},
      {"/proc/version", 559},
      {"/proc/sys/kernel/perf_event_paranoid", 949},

      {"/sys/devices/system/cpu0/cpufreq/cpuinfo_max_freq", 204},
      {"/sys/devices/system/cpu/cpu0/topology/physical_package_id", 803},
      {"/sys/devices/system/cpu/cpu0/topology/core_siblings_list", 441},
      {"/sys/devices/system/cpu/cpu0/topology/cluster_cpus_list", 667},

      {"/sys/devices/system/cpu1/cpufreq/cpuinfo_max_freq", 312},
      {"/sys/devices/system/cpu/cpu1/topology/physical_package_id", 980},
      {"/sys/devices/system/cpu/cpu1/topology/core_siblings_list", 125},
      {"/sys/devices/system/cpu/cpu1/topology/cluster_cpus_list", 760},

      {"/sys/devices/system/cpu2/cpufreq/cpuinfo_max_freq", 518},
      {"/sys/devices/system/cpu/cpu2/topology/physical_package_id", 271},
      {"/sys/devices/system/cpu/cpu2/topology/core_siblings_list", 892},
      {"/sys/devices/system/cpu/cpu2/topology/cluster_cpus_list", 604},

      {"/sys/devices/system/cpu3/cpufreq/cpuinfo_max_freq", 409},
      {"/sys/devices/system/cpu/cpu3/topology/physical_package_id", 744},
      {"/sys/devices/system/cpu/cpu3/topology/core_siblings_list", 96},
      {"/sys/devices/system/cpu/cpu3/topology/cluster_cpus_list", 931}};

  bool inserted = false;

  unsigned int insertions = 0;
  for (const auto& kv : primaryTable) {
    bht.insert(kv.first.c_str(), kv.second);
    insertions++;
  }

  printf("Insertions: %u | Data size: %zu\n\n", insertions, primaryTable.size());

  int val = -1;
  for (const auto& kv : primaryTable) {
    val = bht.retrieve(kv.first.c_str());
    if (val == 0 || val == -1) {
      printf("Something bad for %s\n", kv.first.c_str());
    } else {
      printf("Filename: %s -> FD: %u\n", kv.first.c_str(), val);
    }
  }

  bht.dump();

  printf("===========================================\n");

  val = -1;
  for (const auto& kv : primaryTable) {
    val = bht.retrieve(kv.first.c_str());

    if (val != kv.second) {
      printf("FAIL: %s -> got %d, expected %d\n", kv.first.c_str(), val, kv.second);
    } else {
      printf("OK:   %s -> FD: %d\n", kv.first.c_str(), val);
    }

    assert(val != -1 && "Key not found in table");
    assert(val != 0 && "retrieve() returned 0 (sentinel/missing)");
    assert(val == kv.second && "Retrieved FD does not match expected value");
  }

  printf("All %zu assertions passed.\n", primaryTable.size());

  return 0;
}
