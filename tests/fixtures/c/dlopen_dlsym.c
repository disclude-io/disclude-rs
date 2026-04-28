/* Fixture: C file that dynamically loads a library and resolves a symbol
 * at runtime using a non-literal name — classic obfuscated loader shape.
 */
#include <dlfcn.h>

void load_and_call(const char *lib_path, const char *sym_name) {
    void *handle = dlopen(lib_path, 1);
    void (*fn_ptr)(void) = dlsym(handle, sym_name);
    if (fn_ptr) fn_ptr();
}
