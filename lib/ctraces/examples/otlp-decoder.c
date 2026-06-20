#include <ctraces/ctraces.h>
#include <fluent-otel-proto/fluent-otel.h>

int main()
{
    FILE *fp;
    struct ctrace *ctr;

    char *text;
    char *buf;
    int result;
    int bufsize;
    size_t offset;
    size_t newLen;

    offset = 0;
    bufsize = 0;
    buf = NULL;

    fp = fopen("examples/sample_trace.bin", "rb");

    if (fp != NULL) {
        if (fseek(fp, 0L, SEEK_END) == 0) {

            bufsize = ftell(fp);
            if (bufsize == -1)
            {
                printf("error in reading file size");
            }

            buf = malloc(sizeof(char) * (bufsize + 1));

            if (fseek(fp, 0L, SEEK_SET) != 0) {
                printf("seek error");
            }

            newLen = fread(buf, sizeof(char), bufsize, fp);
            if (ferror(fp) != 0) {
                fputs("Error reading file", stderr);
            }
            else {
                buf[newLen++] = '\0';
            }
        }
        fclose(fp);
    }

    result = ctr_decode_opentelemetry_create(&ctr, buf, bufsize, &offset);
    if (result == -1) {
        printf("Unable to decode trace sample");
    }

    text = ctr_encode_text_create(ctr);
    printf("%s\n", text);
    ctr_encode_text_destroy(text);

    ctr_destroy(ctr);
    free(buf);

    return 0;
}