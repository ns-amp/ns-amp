#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "graph.h"
#include "vector.h"

// TODO: Exclude direct edge from sink to source (unlikely case).
void split(node_t node, unsigned sections, int min) {
  node->split = calloc(sections, sizeof(unsigned));
  int value = node->capacity;
  unsigned i = 0;

  while (value >= 0) {
    if (value >= min) {
      value -= min;
      node->split[i % sections] += min;
      min++;
    } else {
      node->split[i % sections] += value;
      break;
    }

    // randomize
    if (i > sections) i += (int) floor(rand() * 3);
    else i++;
  }
}

int node_exists(vector_t nodes, unsigned id) {
  for (size_t i = 0; i < vector_size(nodes); i++) {
    node_t node = (node_t) vector_get(nodes, i);
    if (node->id == id) return 1;
  }
  return 0;
}

int get_node_by_id_callback(void *data, void *value) {
	node_t node = (node_t) data;
	unsigned id = (unsigned) value;
	return node->id == id;
}

void sort_nodes(vector_t nodes) {
  if (nodes == NULL) {
    fprintf(stderr, "Error: invalid vector.\n");
    exit(1);
  }

  node_t temp;
  unsigned int i, j;
  for (i = 0; i < vector_size(nodes); i++) {
    for (j = 0; j < (vector_size(nodes) - i - 1); j++) {
      node_t node_j = (node_t) vector_get(nodes, j);
      node_t node_j_plus_1 = (node_t) vector_get(nodes, j + 1);
      if (node_j->id > node_j_plus_1->id) {
        temp = (node_t) vector_get(nodes, j);
        vector_set(nodes, j, vector_get(nodes, j + 1));
        vector_set(nodes, j + 1, temp);
      }
    }
  }
}

void sort_edges(vector_t edges) {
  if (edges == NULL) {
    fprintf(stderr, "Error: invalid vector.\n");
    exit(1);
  }

  edge_t temp;
  unsigned int i, j;
  for (i = 0; i < vector_size(edges); i++) {
    for (j = 0; j < (vector_size(edges) - i - 1); j++) {
      edge_t edge_j = (edge_t) vector_get(edges, j);
      edge_t edge_j_plus_1 = (edge_t) vector_get(edges, j + 1);
      if (edge_j->src->id > edge_j_plus_1->src->id) {
        temp = (edge_t) vector_get(edges, j);
        vector_set(edges, j, vector_get(edges, j + 1));
        vector_set(edges, j + 1, temp);
      }
    }
  }
}

unsigned outgoing_edge_count(vector_t edges, node_t node) {
  unsigned count = 0;
  for (size_t i = 0; i < vector_size(edges); i++) {
    edge_t edge = (edge_t) vector_get(edges, i);
    if (edge->src->id == node->id) count++;
  }

  return count;
}

void update_edges_and_nodes(vector_t edges, vector_t nodes, node_t node) {
  unsigned j = 0;
  for (size_t i = 0; i < vector_size(edges); i++) {
    edge_t edge = (edge_t) vector_get(edges, i);
    if (edge->src->id == node->id) {
      edge->weight = node->split[j];

      node_t dest = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) edge->dest->id);
      dest->capacity += edge->weight;
      j++;
    }
  }
}

void generate_dag(vector_t edges, vector_t nodes) {
  unsigned node_count = 0;
  unsigned ranks = MIN_RANKS + (rand() % (MAX_RANKS - MIN_RANKS + 1));
  
  for (size_t i = 0; i < ranks; i++) {
    // New nodes of 'higher' rank than all nodes generated till now.
    unsigned new_nodes = MIN_PER_RANK + (rand () % (MAX_PER_RANK - MIN_PER_RANK + 1));

    // Edges from old nodes ('nodes') to new ones ('new_nodes').
    for (size_t j = 0; j < node_count; j++) {
      for (size_t k = 0; k < new_nodes; k++) {
        if ((rand() % 100) < PERCENT) {
          edge_t edge = malloc(sizeof(edge_st));
          node_t src, dest;

          if (node_exists(nodes, j)) {
            src = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) j);
          } else {
            src = malloc(sizeof(node_st));
            src->id = j;
            src->capacity = 0;
            vector_add(nodes, src);
          }
          
          if (node_exists(nodes, k + node_count)) {
            dest = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) k + node_count);
          } else {
            dest = malloc(sizeof(node_st));
            dest->id = k + node_count;
            dest->capacity = 0;
            vector_add(nodes, dest);
          }

          edge->src = src;
          edge->dest = dest;
          vector_add(edges, edge);
        }
      }
    }

    node_count += new_nodes; // Accumulate into the old node set.
  }
}

vector_t connect_source_sink(vector_t edges, vector_t nodes) {
  const unsigned source_id = 0;
  const unsigned sink_id = vector_size(nodes) + 1;
  vector_t updated_edges = vector_dup(edges);

  if (!node_exists(nodes, source_id)) {
    node_t source = malloc(sizeof(node_st));
    source->id = source_id;
    source->capacity = 0;
    vector_add(nodes, source);
  }
  
  if (!node_exists(nodes, sink_id)) {
    node_t sink = malloc(sizeof(node_st));
    sink->id = sink_id;
    sink->capacity = 0;
    vector_add(nodes, sink);
  }

  for (size_t i = 0; i < vector_size(edges); i++) {
    int is_dest = 0, is_src = 0;
    edge_t edge = (edge_t) vector_get(edges, i);

    for (size_t j = 0; j < vector_size(updated_edges); j++) {
      if (i == j) continue;
      
      edge_t other_edge = (edge_t) vector_get(updated_edges, j);
      if (edge->src->id == other_edge->dest->id) is_dest = 1;
      if (edge->dest->id == other_edge->src->id) is_src = 1;
    }

    if (!is_dest && edge->src->id != source_id) {
      edge_t e = malloc(sizeof(edge_st));
      e->src = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) source_id);
      e->dest = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) edge->src->id);
      vector_add(updated_edges, e);
    }
    if (!is_src && edge->dest->id != sink_id) {
      edge_t e = malloc(sizeof(edge_st));
      e->src = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) edge->dest->id);
      e->dest = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *)   sink_id);
      vector_add(updated_edges, e);
    }
  }

  return updated_edges;
}

int main(void) {
  srand(time(NULL));

  int is_valid = 0;
  while (!is_valid) {
    vector_t edges = vector_init(1);
    vector_t nodes = vector_init(1);
    generate_dag(edges, nodes);

    vector_t updated_edges = connect_source_sink(edges, nodes);
    sort_edges(updated_edges);
    sort_nodes(nodes);

    const unsigned node_count = vector_size(nodes);
    const unsigned value = (rand() % node_count) + node_count;
    const unsigned source_id = 0;

    node_t source = (node_t) vector_get_by_value(nodes, get_node_by_id_callback, (void *) source_id);
    source->capacity = value;
    unsigned source_outgoing_edges = outgoing_edge_count(updated_edges, source);
    split(source, source_outgoing_edges, 1);
    update_edges_and_nodes(updated_edges, nodes, source);
    
    int should_continue = 0;
    for (size_t i = 1; i < vector_size(nodes) - 1; i++) {
      node_t node = (node_t) vector_get(nodes, i);
      unsigned node_outgoing_edges = outgoing_edge_count(updated_edges, node);
      if (node_outgoing_edges > 0 && node->capacity >= node_outgoing_edges) {
        split(node, node_outgoing_edges, 1);
        update_edges_and_nodes(updated_edges, nodes, node);
      } else {
        should_continue = 1;
      }
    }

    if (should_continue || node_count < MIN_NODES) {
      vector_free(nodes);
      vector_free(edges);
      vector_free(updated_edges);
      continue;
    }

    FILE *fp = fopen("graph.dot", "w");
    if (fp == NULL) {
      fprintf(stderr, "Error: could not open the file.\n");
      return 1;
    }

    fprintf(fp, "digraph {\n");
    for (size_t i = 0; i < vector_size(updated_edges); i++) {
      edge_t edge = (edge_t) vector_get(updated_edges, i);
      if (edge->weight != 0) {
        fprintf(fp, "  %u -> %u [label=\"%u\"];\n", edge->src->id, edge->dest->id, edge->weight);
      }
    }
    fprintf(fp, "}\n");
    fclose(fp);

    fp = fopen("graph.metadata", "w");
    if (fp == NULL) {
      fprintf(stderr, "Error: could not open the file.\n");
      return 1;
    }

    fprintf(fp, "value: %u\t", value);
    fprintf(fp, "nodes: %u\n", node_count);
    for (size_t i = 0; i < node_count; i++) {
      node_t node = (node_t) vector_get(nodes, i);
      fprintf(fp, "id: %u\taddress: tcp://localhost:81%s%u\n", node->id, node->id < 10 ? "0" : "", node->id);
    }
    fclose(fp);

    printf("Generated graph with %u nodes and %u edges.\n", node_count, vector_size(updated_edges));

    vector_free(nodes);
    vector_free(edges);
    vector_free(updated_edges);
    is_valid = 1;
  }

  return 0;
}