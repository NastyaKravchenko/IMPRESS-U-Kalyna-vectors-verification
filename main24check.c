#include <stdio.h>
#include <memory.h>

#include "kalyna.h"
#include "transformations.h"

#define MAX_BLOCKS_PER_LINE 4
/* for  128-256 */

void print (size_t data_size, uint64_t* data)
{
	int i;
	uint8_t * tmp = (uint8_t *) data; 
	for (i = 0; i < data_size * 8; i ++)
	{
		if (! (i % 16)) printf ("    ");
		printf ("%02X", (unsigned int) tmp [i]);
		if (!((i + 1) % 16)) printf ("\n");
	};
	printf ("\n");
};

int charToHex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; 
}

uint64_t swap_endian_64(uint64_t num) {
    return ((num >> 56) & 0x00000000000000FF) | 
           ((num >> 40) & 0x000000000000FF00) | 
           ((num >> 24) & 0x0000000000FF0000) | 
           ((num >> 8) & 0x00000000FF000000) | 
           ((num << 8) & 0x000000FF00000000) | 
           ((num << 24) & 0x0000FF0000000000) | 
           ((num << 40) & 0x00FF000000000000) | 
           ((num << 56) & 0xFF00000000000000);
}

void processString(char* str, uint64_t arr[MAX_BLOCKS_PER_LINE]) {
    size_t len = strlen(str);
    if (str[len - 1] == '\n') str[len - 1] = '\0'; // ��������� ������ ������ �����
    int j;
    int Nb = len / 16;
    for (j = 0; j < Nb; j++) {
        unsigned long long l = 0;
        size_t i;
        for (i = 0; i < 16; i++) {
            l = charToHex(str[j * 16 + i]) + (l << 4);
        }
        arr[j]=swap_endian_64(l);
    }
}

int main(int argc, char** argv) {
   
	int i;
	kalyna_t* ctx24_e = KalynaInit(128, 256);
    uint64_t key24_e[4], ct24_e[2], pt24_e[2], expect24_e[2];

    
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <plaintext_file> <key_file> <ecnrypted_file>\n", argv[0]);
        return 1;
    }
    
    FILE *plaintext_file = fopen(argv[1], "r");
    FILE *key_file = fopen(argv[2], "r");
    FILE *encrypted_file = fopen(argv[3], "r");
    if (!plaintext_file || !key_file || !encrypted_file) {
        fprintf(stderr, "Error opening files.\n");
        return 1;
    }
    char str_pt[129], str_key[257], str_enc[129]; 
    int n;
    n = 0;
    printf("\n=============\n");
        printf("Kalyna (%lu, %lu) check\n", ctx24_e->nb * 64, ctx24_e->nk * 64);
        
    while (fscanf(plaintext_file, "%[^\n]", str_pt) == 1 && fscanf(key_file, "%[^\n]", str_key) == 1 && fscanf(encrypted_file, "%[^\n]", str_enc) == 1){

        fscanf(plaintext_file, "%*c");
    	fscanf(key_file, "%*c");
    	fscanf(encrypted_file, "%*c");
         
         processString(str_pt, pt24_e);
	     processString(str_key, key24_e);
	     processString(str_enc, expect24_e);
	     
    	KalynaKeyExpand(key24_e, ctx24_e);
        
        KalynaEncipher(pt24_e, ctx24_e, ct24_e);
        
    	if (memcmp(ct24_e, expect24_e, sizeof(ct24_e)) != 0) printf("Failed enciphering\n");
    	
    	if (expect24_e[0]!=ct24_e[0] || expect24_e[1]!=ct24_e[1]){
           printf("Test is failed! String %d:\n\n", n+1);
           printf("Ciphertext:\n");
           print(ctx24_e->nb, ct24_e);
           printf("Ciphertext (expected):\n");
           print(ctx24_e->nb, expect24_e);
           return -1;
        } else n++;
    } printf("\nEncryption is successful, results are as expected!\nChecked %d pairs\n", n);

	fclose(plaintext_file);
    fclose(key_file);
    fclose(encrypted_file);
    return 0;
}
