#ifndef BIPAN_HASH_TABLE_HPP
#define BIPAN_HASH_TABLE_HPP

#define MAX_TABLE_SIZE 30
// putting to half for simplicity, not many files to spoof
#define MAX_CHAINING_LIST_SIZE(x) MAX_TABLE_SIZE / 2

#define MAX_KEY_LEN 256

// Should be 16 bytes
typedef struct _node {
  char key[MAX_KEY_LEN];  // for differentiating nodes on chaining
  int val;                // the actual FD
  struct _node* next;     // for chaining, if necessary
} Node;

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
  BipanHashTable();
  void insert(const char* name, int fd);
  int retrieve(const char* name);
  void dump();
  ~BipanHashTable();

 private:
  // Members
  unsigned char maxPrimaryTableSize;
  unsigned char maxChainingListSize;
  Node primaryTable[MAX_TABLE_SIZE];
  unsigned char chainingListIdx;
  Node chainingList[MAX_CHAINING_LIST_SIZE(MAX_TABLE_SIZE)];
  // Methods

  unsigned int hash(const char* name);
  int allocate(const char* name, int val, Node* next);
};

#endif  // BIPAN_HASH_TABLE_HPP