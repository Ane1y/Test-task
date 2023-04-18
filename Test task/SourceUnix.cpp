#include "std_testcase.h"

#include <cwchar>
#include <ios>
#include <iostream>
#include <dlfcn.h>

void CWE114_Process_Control__w32_char_file_01_bad() {
    char *data;
    char buff[100] = "";
    const char* FILENAME{"/tmp/file.txt"};
    const char mode[]{"r"};
    FILE* file = fopen(FILENAME, mode);

    if (!file) {
        fprintf(stderr, "Cannot open the file\n");
        return;
    }
    while(true) {
        size_t bytes_read = fread(buff, 1, sizeof(buff), file);
        if (!bytes_read) {
            break;
        }
    }
    fclose(file);

    data = buff;

    {
        void* module;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        module = dlopen(data, RTLD_LAZY);
        if (module) {
            dlclose(module);
            printf("Library loaded and freed successfully\n");
        } else {
            printf("Unable to load library\n");
        }
    }
}


/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B() {
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "/lib64/libsframe.so");
    {
        void* module;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        module = dlopen(data, RTLD_NOW);
        if (module) {
            dlclose(module);
            printf("Library loaded and freed successfully \n");
        } else {
            printf("Unable to load library\n");
        }
    }
}

void CWE114_Process_Control__w32_char_file_01_good() {
    goodG2B();
}


/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */



int main(int argc, char *argv[]) {
    /* seed randomness */
    srand((unsigned) time(NULL));
    printf("Calling good()... \n");
    CWE114_Process_Control__w32_char_file_01_good();
    printf("Finished good() \n");

    printf("Calling bad()...\n");
    CWE114_Process_Control__w32_char_file_01_bad();
    printf("Finished bad() \n");
    return 0;
}

