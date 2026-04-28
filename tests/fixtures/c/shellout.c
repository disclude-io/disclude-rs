/* Fixture: C file that spawns a shell command via system() — supply-chain
 * attack shape: the command string is constructed at runtime from a variable.
 */
#include <stdlib.h>

void run_command(const char *cmd) {
    system(cmd);
}
