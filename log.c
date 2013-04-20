#include <stdio.h>
#include <string.h>

int dbd_log(char *message){
    FILE *fp;
    if(!(fp = fopen("log", "a"))){
        printf("cannot open log file");
        return -1;
    }
    fputs(message, fp);
    fputc('\n', fp);
    fclose(fp);
    return 0;
}
