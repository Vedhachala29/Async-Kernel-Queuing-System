#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include <stdbool.h> 
#include <err.h>
#include "workqueue.h"

# define KEY_LENGTH 16
# define MAX_SIZE 256

#define NEW_TASK _IOW('a','a',int32_t*)
#define RD_VALUE _IOR('a','b',int32_t*)

int inFilesCount = 0, jobPriority = 0, outFilesCount = 0;
struct file_details **infiles = NULL, **outfiles = NULL;
char *password=NULL,*buf=NULL;
bool priorityFlag, deleteFlag, renameFlag, decryptFlag, encryptFlag, passwordFlag, hashFlag, statFlag, compressFlag, decompressFlag, concatFlag;
bool operation = false;
char *key = NULL;
char *temp = NULL, *pwd = NULL;
char temp1[MAX_SIZE];
enum job_type jobtype;
struct __user_job_struct *job;
char * getRealPath(char *filename);

int validateInput(){
    printf("validating the input\n");
    struct stat buffer;
    for(int i=0;i<inFilesCount;i++){
        int exist = stat(infiles[i]->filename,&buffer);
        if(exist != 0){
            printf("input file : %s is missing. Please verify and try again\n",infiles[i]->filename);
            return EINVAL;
        }
    }
    return 0;
}


void printJobArgs(){
    printf("printing job args\n");
    printf("job priority is : %d\n",job->priority);
    printf("job type is %d\n", (int)(job->job_type));
    printf("in files count is %d\n",job->input_files_count);
    printf("out files count is %d\n",job->output_files_count);
    for(int j=0;j<job->input_files_count;j++){
        printf("infile %d is %s of size %d\n",j+1, job->input_files[j]->filename, job->input_files[j]->len);
    }
    for(int j=0;j<job->output_files_count;j++){
        printf("outfile %d is %s of size %d\n",j+1, job->output_files[j]->filename, job->output_files[j]->len);
    }
    if(key)
        printf("key is %s\n",job->key);
    printf("key len is %d\n",job->key_length);
}

void prepareWorkStruct(){
    printf("preparing the job struct\n");
    job->job_type = jobtype;
    job->priority = jobPriority;
    if(passwordFlag){
        job->key = key;
        job->key_length = KEY_LENGTH;
    }
    else{
        job->key = NULL;
        job->key_length = 0;
    }
    job->input_files_count = inFilesCount;
    job->output_files_count = outFilesCount;
    printf("job->input_files_count %d\n",job->input_files_count);
    printf("job->output_files_count %d\n",job->output_files_count);
    job->input_files = infiles;
    job->output_files = outfiles;
    job->priority = jobPriority;
}

void createKey(void *buf, char *password){
    if(password!=NULL){ 
        if(strlen(password) < 6){
            printf("Minimum length of the password should be 6 characters\n");
            exit(EXIT_FAILURE);
        } 
        else{
            key = (char *)MD5((const unsigned char *)password, strlen(password), buf);
            if(!key){
                printf("Key generation failed from password\n");
                exit(EXIT_FAILURE);
            } 
        }
    }
    else
        buf = NULL;              
} 

int checkOperation(){
    if(operation){
        printf("only one operation is permitted.");
        return EINVAL;
    }
    return 0;
}

void allocateInputFiles(int *argc, int *optind, char *argv[]){
    int i=0;
    infiles = malloc( sizeof(struct file_details *) * (*argc - *optind) );
    for(; *optind < *argc; *optind = *optind+1){
        infiles[i] = malloc(sizeof(struct file_details));
        // temp = malloc( sizeof(char) * (strlen(argv[*optind] + 1)) );
        temp = malloc( sizeof(char) * 256);
        temp = argv[*optind];
        temp[strlen(argv[*optind])] = '\0';
        if(getRealPath(temp))
            temp = getRealPath(temp);
        else{
            strcpy(temp1,pwd);
            strcat(temp1,temp);
            strcpy(temp,temp1);
        }
        infiles[i]->filename = temp;
        infiles[i]->len = strlen(temp);
        i++;
        printf("i %d\n",i);
    }
    inFilesCount = i;
}

void allocateInputOutputFiles(int *argc, int *optind,char *argv[]){
    int i = 0;
    char *temp;
    infiles = malloc(sizeof(struct file_details *)*((*argc - *optind)/2));
    outfiles = malloc(sizeof(struct file_details *)*((*argc - *optind)/2));
    for(; *optind < *argc; *optind = *optind + 1){
        infiles[i] = malloc(sizeof(struct file_details));
        outfiles[i] = malloc(sizeof(struct file_details));
        temp = malloc(sizeof(char)*(strlen(argv[*optind] + 1)));
        temp = argv[*optind];
        temp[strlen(argv[*optind])] = '\0';
        if(getRealPath(temp))
            temp = getRealPath(temp);
        else{
            strcpy(temp1,pwd);
            strcat(temp1,temp);
            strcpy(temp,temp1);
        }
        infiles[i]->filename = temp;
        infiles[i]->len = strlen(temp);
        *optind = *optind + 1;
        temp = malloc(sizeof(char)*(strlen(argv[*optind] + 1)));
        temp = argv[*optind];
        temp[strlen(argv[*optind])] = '\0';
        temp = getRealPath(temp);
        outfiles[i]->filename = temp;
        outfiles[i]->len = strlen(temp);
        i++;
    }
    inFilesCount = i;
    outFilesCount = i;
}
void allocateOutputFiles(int *argc, int *optind,char *argv[]){
    int i=0;
    outfiles = malloc(sizeof(struct file_details *) * ( *argc - *optind));
    for(; *optind < *argc; *optind = *optind+1){
        outfiles[i] = malloc(sizeof(struct file_details));
        char *temp = malloc(sizeof(char)*(strlen(argv[*optind] + 1)));
        temp = argv[*optind];
        temp[strlen(argv[*optind])] = '\0';
        if(getRealPath(temp))
            temp = getRealPath(temp);
        else{
            strcpy(temp1,pwd);
            strcat(temp1,temp);
            strcpy(temp,temp1);
        }
        outfiles[i]->filename = temp;
        outfiles[i]->len = strlen(temp);
        i++;
        printf("i %d\n",i);
    }
    outFilesCount = i;
}

char * getRealPath(char *filename){
    return realpath(filename, NULL);
}

int main(int argc,  char *argv[]){
    int rc =0;
    int fd = 0;
    int opt=0;
    int32_t number;
    pwd = malloc(sizeof(char)*256);
    getcwd(pwd, 256);
    printf("pwd is %s\n",pwd);
    strcat(pwd,"/");
    while (optind < argc && (opt = getopt(argc,  argv, "pjdrschexlm")) != -1) {
        switch(opt){
            // optional flag = j
            case 'j' :
                priorityFlag = true;
                printf("jobPriority is : %s\n", argv[optind]);
                jobPriority = atoi(argv[optind++]);
                printf("jobPriority is : %d\n", jobPriority);
                break;

            case 'd' :
                if(checkOperation() != 0)
                    return EINVAL;
                deleteFlag = true;
                operation = true;
                jobtype = DELETE_FILES;
                printf("argument d has been passed for deleting the files\n");
                printf("list of files to be deleted are :\n");
                allocateInputFiles(&argc, &optind, argv);
                break;
 
            case 'p' :
                printf("password is passed\n");
                passwordFlag = true;
                password = malloc(sizeof(char)*( strlen(argv[optind] + 1)));
                password[strlen(argv[optind])] = '\0';
                password = argv[optind++];
                void *buf = malloc(16 * sizeof(char)); 
                createKey(buf, password);
                break;

            case 'e' :
                if(checkOperation() != 0)
                    return EINVAL;
                if(passwordFlag == 0){
                    printf("Please enter password for encryption via -p option");
                }
                encryptFlag = true;
                operation = true;
                jobtype = ENCRYPT_FILE;
                printf("argument e has been passed for encryption\n");
                argc--;
                allocateInputFiles(&argc, &optind, argv);
                argc++;
                printf("optind %d argc %d\n", optind, argc);
                allocateOutputFiles(&argc, &optind, argv);
                break;

            case 'x' :
                if(checkOperation() != 0){
                    return EINVAL;
                }
                if(passwordFlag == 0){
                    printf("Please enter password for decryption via -p option");
                }
                decryptFlag = true;
                operation = true;
                jobtype = DECRYPT_FILE;
                printf("argument x has been passed for decryption\n");
                argc--;
                allocateInputFiles(&argc, &optind, argv);
                argc++;
                allocateOutputFiles(&argc, &optind, argv);
                break;

            case 'r' :
                if(checkOperation() != 0)
                    return EINVAL;
                renameFlag = true;
                operation = true;
                jobtype = RENAME_FILES;
                printf("argument r has been passed for renaming the files\n");
                printf("list of input files:\n");
                if((argc-optind)%2)
                {
                    printf("Filenames count should be even");
                    return -1;
                }
                allocateInputOutputFiles(&argc, &optind, argv);
                break;

            case 'h' :
                if(checkOperation() != 0)
                    return EINVAL;
                printf("argument h has been passed for hasing the files");
                hashFlag = true;
                operation = true;
                jobtype = COMPUTE_AND_RETURN_HASH_OF_A_FILE;
                allocateInputFiles(&argc, &optind, argv);
                break;

            case 's' :
                if(checkOperation() != 0)
                    return EINVAL;
                printf("argument s has been passed for stating the files");
                statFlag = true;
                operation = true;
                jobtype = STAT_FILES;
                allocateInputFiles(&argc, &optind, argv);
                break;

            case 'c' :
                if(checkOperation() != 0)
                    return EINVAL;
                printf("argument c has been passed for compressing the files");
                compressFlag = true;
                operation = true;
                jobtype = COMPRESS_FILE;
                allocateInputFiles(&argc, &optind, argv);
                break;

            case 'l' :
                if(checkOperation() != 0)
                    return EINVAL;
                printf("argument l has been passed for decompressing the files");
                decompressFlag = true;
                operation = true;
                jobtype = DECOMPRESS_FILE;
                allocateInputFiles(&argc, &optind, argv);
                break;
            
            case 'm' :
                if(checkOperation() != 0)
                    return EINVAL;
                concatFlag = true;
                operation = true;
                jobtype = CONCATANATE_FILES;
                argc--;
                allocateInputFiles(&argc, &optind, argv);
                argc++;
                allocateOutputFiles(&argc, &optind, argv);
                break;
        }
    }
    rc = validateInput();
    if(rc!=0){
        printf("rc is %d\n",rc);
        goto out;
    }
    job = malloc(sizeof(struct __user_job_struct));
    if(infiles==NULL)
    {
        printf("No input files provided.\n");
        rc = -ENOENT;
        goto out;
    }
    if( (renameFlag || concatFlag || encryptFlag || decryptFlag) && outfiles == NULL){
        printf("No Output files provided.\n");
        rc = -ENOENT;
        goto out;
    }
    /* preparing job struct */
    prepareWorkStruct();
    /* printing job args */
    printJobArgs();
    
    printf("calling the ioctl function");
    printf("\nOpening Driver\n");
    fd = open("/dev/etx_device", O_RDWR);
    if(fd < 0) {
            printf("Cannot open device file...\n");
            return 0;
    }

    printf("Enter the Value to send\n");
    scanf("%d",&number);
    printf("Writing Value to Driver\n");
    rc = ioctl(fd, NEW_TASK, (int32_t*) job); // rc will be job id
    printf("Closing Driver\n");
    close(fd); 
out:
    if(buf)
        free(buf);
    if(key)
        free(key);
    if(job)
        free(job);
    if(temp)
        free(temp);
    if(outfiles)
        free(outfiles);
    if(infiles)
        free(infiles);
    free(pwd);
    return rc;
}
