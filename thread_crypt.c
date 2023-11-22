#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <crypt.h>
#include <sys/stat.h>
#include "thread_crypt.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	int algo;
	int saltLen;
	int rounds;			// default options variables
	int rFlag;
	int seed;
	char *fileContents;
	FILE *ofd;
} CryptOptions;

void *input(void *);

int main(int argc, char *argv[]) {

	CryptOptions opsData = {0, 2, 5000, 0, 1, NULL, stdout};
	//——————————————————	
	int iFlag = 0;
	int oFlag = 0;				// command line option flags
	int lFlag = 0;
	//——————————————————
	int numThreads = 1;	
	FILE *ifd = NULL;
	char *fileName = NULL;
	pthread_t *threads = NULL;
	struct stat data;

	{
		int opt = -1;

		if(argc <= 1) {
			fprintf(stderr, "no action supplied\nexiting without doing ANYTHING...\n");
			exit(EXIT_FAILURE);
		}

		while((opt = getopt(argc, argv, OPTIONS)) != -1) {
			switch(opt) {
			
				case 'i':											// processing input file	
					iFlag = 1;
					fileName = optarg;

					ifd = fopen(fileName, "r");
					if(ifd == NULL) {
						perror("failed to open input file!\n");
						exit(EXIT_FAILURE);
					}
						
					if(stat(fileName, &data) == -1) {
						perror("failed to stat file!\n");
						exit(EXIT_FAILURE);
					}
					
					opsData.fileContents = (char*) calloc(data.st_size + 1, sizeof(char));
					fread(opsData.fileContents, 1, data.st_size, ifd);									
					break;
				
				case 'o':											// processing output
					oFlag = 1;	

					opsData.ofd = fopen(optarg, "w");
					if(opsData.ofd == NULL) {
						perror("failed to open output file!\n");
						exit(EXIT_FAILURE);
					}
					break;
		
				case 'h':
					printf("./thread_crypt ...\n"
							"\tOptions: i:o:hva:l:R:t:r:\n"
							"\t-i file         input file name (required)\n"
							"\t-o file         output file name (default stdout)\n"
							"\t-a #            algorithm to use for hashing [0,1,5,6] (default 0 = DES)\n"
							"\t-l #            length of salt (default 2 for DES, 8 for MD-5, 16 for SHA)\n"
							"\t-r #            rounds to use for SHA-256, or SHA-512 (default 5000)\n"
							"\t-R #            seed for rand() (default none)\n"
							"\t-t #            number of threads to create (default 1)\n"
							"\t-v              enable verbose mode\n"
							"\t-h              helpful text\n");	
					break;
	
				case 'v':
					fprintf(stderr, "Verbose mode enabled.\n");
					break;

				case 'a':														// processing algorithm type				
					opsData.algo = strtol(optarg, (char**) NULL, 10);

					if(opsData.algo != 0 && opsData.algo != 1 && opsData.algo != 5 && opsData.algo != 6) {
						fprintf(stderr, "invalid algorithm! see -h for more info\n");
						exit(EXIT_FAILURE);
					}	
					break;

				case 'l':														// processing salt length
					lFlag = 1;	
					opsData.saltLen = strtol(optarg, (char **) NULL, 10);

					if(opsData.algo == 0) {
						opsData.saltLen = 2;	
					}
					else if(opsData.algo == 1) {								// validating salt length for MD-5
						if(opsData.saltLen > 8) opsData.saltLen = 8;
						else if(opsData.saltLen < 4) opsData.saltLen = 4;
					}
					else {														// validating salt length for SHA256 and SHA512
						if(opsData.saltLen > 16) opsData.saltLen = 16;	
						else if(opsData.saltLen < 8) opsData.saltLen = 8;
					}	
					break;

				case 'R':	
					opsData.rFlag = 1;											// processing seed
					opsData.seed = strtol(optarg, (char **) NULL, 10);	
					break;

				case 't':														// processing # of threads	
					numThreads = strtol(optarg, (char **) NULL, 10);
					
					if(numThreads <= 0 || numThreads > 20) {
						fprintf(stderr, "invalid number of threads!\n");
						exit(EXIT_FAILURE);	
					}
					break;

				case 'r':														// processing # of rounds
					opsData.rounds = strtol(optarg, (char **) NULL, 10);

					if(opsData.rounds < 1000) opsData.rounds = 1000;
					else if(opsData.rounds > 999999999) opsData.rounds = 999999999;
					break;
				
				default:
					break;
			}
		}
	}
	
	if(iFlag == 0) {
		fprintf(stderr, "input file not provided!\n");
		exit(EXIT_FAILURE);
	}

	if(lFlag == 0 && opsData.algo != 0) {        // setting the default salt length for a given algorithm if not option specified
		if(opsData.algo == 1) {
			opsData.saltLen = 8;
		}
		else {
			opsData.saltLen = 16;
		}
	}

	threads = malloc(numThreads * sizeof(pthread_t));		
		
	for(int tid = 0; tid < numThreads; tid++) {								// setting threads loose on the world
		pthread_create(&threads[tid], NULL, input, (void *) &opsData);
	}
	for(int tid = 0; tid < numThreads; tid++) {
		pthread_join(threads[tid], NULL);
	}	

	if(oFlag == 1) fclose(opsData.ofd);
	fclose(ifd);
	free(threads);
	free(opsData.fileContents);
		
	return EXIT_SUCCESS;
}

void *input(void * voidOpsData) {
	
	static const char salt_chars[] = {SALT_CHARS};
	static int tokFlag = 0;
	CryptOptions *opsData = (CryptOptions *) voidOpsData;
	char *preHash = NULL;
	char *token = NULL;
	char shortSalt[opsData->saltLen + 1];
	char tempRounds[17];
	struct crypt_data data;

	do {
		data.initialized = 0;									// must be newly reset each time its used
		pthread_mutex_lock(&mutex);								// mutex for strok()

		if(!tokFlag) {
			tokFlag = 1;
			token = strtok(opsData->fileContents, "\n");
		}
		else {
			token = strtok(NULL, "\n");
		} 

		pthread_mutex_unlock(&mutex);

		if(token != NULL) {
			if(opsData->rFlag == 1) srand(opsData->seed);				// seeding rand if rFlag is set

			for(int i = 0, rand_val = 0; i < opsData->saltLen; i++) {	// generating a salt for a given salt length
				rand_val = rand();
				rand_val %= strlen(salt_chars);
				shortSalt[i] = salt_chars[rand_val];
			}
			
			switch(opsData->algo) {										// formatting the salt for crypt_r() depending on algorithm choice

				case 0:
					preHash = (char *) malloc(opsData->saltLen + 1);
					shortSalt[opsData->saltLen] = '\0';
					strcpy(preHash, shortSalt);
					break;

				case 1:
					preHash = (char *) malloc(opsData->saltLen + 5);
					shortSalt[opsData->saltLen] = '\0';
					sprintf(preHash, "$%d$%s$", opsData->algo, shortSalt);
					break;

				case 5:
				case 6:
					sprintf(tempRounds, "rounds=%d", opsData->rounds);
					preHash = (char *) malloc(opsData->saltLen + 38);
					shortSalt[opsData->saltLen] = '\0';
					sprintf(preHash, "$%d$%s$%s$", opsData->algo, tempRounds, shortSalt);
					break;

				default:
					fprintf(stderr, "how did you even get here? this should already be validated...\n");
					exit(EXIT_FAILURE);
					break;
			}

			crypt_r(token, preHash, &data);
			fprintf(opsData->ofd, "%s:%s\n", token, data.output);
			free(preHash);
		}

	} while(token != NULL);

	pthread_exit(EXIT_SUCCESS);
}