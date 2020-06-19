#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Error: invalid arguments.\nUsage: %s mt\n", argv[0]);
    exit(1);
  }

  char *mt = argv[1];

  FILE *fp = fopen("graph.metadata", "r");
  if (fp == NULL) {
    fprintf(stderr, "Error: file not found.\n");
    exit(1);
  }

  size_t len;
  ssize_t read;
  char *line = NULL;

  char value[3];
  unsigned nodes = 0;
  if ((read = getline(&line, &len, fp)) != -1) {
    if (2 != sscanf(line, "%*[^0123456789]%s%*[^0123456789]%u", &value, &nodes)) {
      fprintf(stderr, "Error: could not parse the file.\n");
      exit(1);
    }
  }

  char **id = malloc(sizeof(char *) * (nodes + 1));
  char **address = malloc(sizeof(char *) * (nodes + 1));
  for (size_t i = 0; i < nodes; i++) {
    int int_id;
    char *inter_id = calloc(3, sizeof(char));
    char *inter_address = calloc(25, sizeof(char));
    fscanf(fp, "id: %d\taddress: %s\n", &int_id, inter_address);

    sprintf(inter_id, "%d", int_id);
    id[i] = inter_id;
    address[i] = inter_address;
  }
  id[nodes] = NULL;
  address[nodes] = NULL;

  pid_t pid[nodes];
  pid_t receiver = pid[nodes - 1];
  receiver = fork();
  if (receiver == 0) {
    char *args[] = { "./receiver", id[nodes - 1], address[nodes - 1], mt, NULL };
    char *env[] = { NULL };
    execve("./receiver", args, env);
    _exit(1);
  } else if (receiver == -1) {
    fprintf(stderr, "Error: failed to fork receiver.\n");
    exit(1);
  }

  for (size_t i = nodes - 2; i > 0; i--) {
    pid_t intermediary = pid[i];
    intermediary = fork();
    if (intermediary == 0) {
      char *args[] = { "./intermediary", id[i], address[i], mt, NULL };
      char *env[] = { NULL };
      execve("./intermediary", args, env);
      _exit(1);
    } else if (intermediary == -1) {
      fprintf(stderr, "Error: failed to fork intermediary (%zu).\n", i);
      exit(1);
    }
  }

  pid_t sender = pid[0];
  sender = fork();
  if (sender == -1) {
    fprintf(stderr, "Error: failed to fork sender.\n");
    exit(1);
  } else if (sender > 0) {
    int status;
    waitpid(sender, &status, 0);
  } else {
    char *args[] = { "./sender", id[0], address[0], address[nodes - 1], value, mt, NULL };
    char *env[] = { NULL };
    execve("./sender", args, env);
    _exit(1);   // exec never returns
  }

  for (size_t i = 0; i < nodes; i++) free(id[i]);
  free(id);
  for (size_t i = 0; i < nodes; i++) free(address[i]);
  free(address);

  return 0;
}
