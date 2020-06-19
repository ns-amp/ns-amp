#ifndef MPMHL_NOAS_INCLUDE_GRAPH
#define MPMHL_NOAS_INCLUDE_GRAPH

#include "vector.h"

#define MIN_NODES    8
#define MIN_PER_RANK 1  // Specifies how fat the DAG should be.
#define MAX_PER_RANK 5
#define MIN_RANKS    3  // Specifies how tall the DAG should be.
#define MAX_RANKS    5
#define PERCENT      30 // Chance of having an edge.

typedef struct {
  unsigned id;
  unsigned capacity;
  unsigned *split;
} node_st;

typedef node_st *node_t;

typedef struct {
  node_t src;
  node_t dest;
  unsigned weight;
} edge_st;

typedef edge_st *edge_t;

void split(node_t node, unsigned sections, int min);
int node_exists(vector_t nodes, unsigned id);
int get_node_by_id_callback(void *data, void *value);
void sort_nodes(vector_t nodes);
void sort_edges(vector_t edges);
unsigned outgoing_edge_count(vector_t edges, node_t node);
void update_edges_and_nodes(vector_t edges, vector_t nodes, node_t node);
void generate_dag(vector_t edges, vector_t nodes);
vector_t connect_source_sink(vector_t edges, vector_t nodes);

#endif // MPMHL_NOAS_INCLUDE_GRAPH