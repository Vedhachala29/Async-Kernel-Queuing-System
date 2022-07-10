#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include <stdbool.h> 
#include <time.h>

#include "workqueue.h"

#define POLL_OPS _IOW('a','c',int32_t*)
#define STATUS_OPS _IOW('a','d',int32_t*)
#define LIST_OPS _IOW('a','e',int32_t*)
#define DELETE_OPS _IOW('a','f',int32_t*)
#define REORDER_OPS _IOW('a','g',int32_t*)

bool pollFlag = false, statusFlag = false,listFlag = false, deleteFlag = false, reorderFlag = false;
struct reorder_ops *reorder_struct = NULL;
struct __user_job_status *user_job_status = NULL;
struct __user_list_jobs *user_list_jobs = NULL;
struct __user_reorder_job *user_reorder_jobs = NULL;
typedef enum operation_type{
    POLL,
    STATUS,
    LIST,
    DELETE,
    REORDER
} operation_type;

int main(int argc,  char *argv[]){
    int rc =0;
    int fd = 0;
    int opt=0, jobId=-1, jobPriority=-1;
    time_t T = time(NULL);
    struct tm tm = *localtime(&T);
    char timestamp[10];
    operation_type operation_type;
    int32_t number;
    while (optind < argc && (opt = getopt(argc,  argv, "cpdrl")) != -1) {
        switch(opt){
            case 'p' :
                printf("poll jobs from queue\n");
                pollFlag = true;
                operation_type = POLL;
                jobId = atoi(argv[optind++]);
                user_job_status = malloc(sizeof(struct __user_job_status));
                user_job_status->jobid = jobId;
                user_job_status->result = malloc(256);
                break;
            case 'c' :
                printf("check status of job id from queue\n");
                statusFlag = true;
                jobId = atoi(argv[optind++]);
                operation_type = STATUS;
                break;
            case 'l' :
                printf("listing the queue jobs");
                listFlag = true;
                sprintf(timestamp, "%02d%02d%02d",tm.tm_hour, tm.tm_min, tm.tm_sec);
                user_list_jobs = malloc(sizeof(struct __user_list_jobs));
                user_list_jobs->timestamp = atoi(timestamp);
                printf("user_list_jobs->timestamp is %d\n", user_list_jobs->timestamp);
                user_list_jobs->result = malloc(sizeof(char)* 2048);
                operation_type = LIST;
                break;
            case 'd' :
                printf("delete the job from the queue");
                deleteFlag = true;
                jobId = atoi(argv[optind++]);
                operation_type = DELETE;
                break;
            case 'r' :
                printf("reorder the job from the queue");
                reorderFlag = true;
                jobId = atoi(argv[optind++]);
                jobPriority = atoi(argv[optind++]);
                operation_type = REORDER;
                user_reorder_jobs = malloc(sizeof(struct __user_reorder_job));
                user_reorder_jobs->jobid = jobId;
                user_reorder_jobs->priority = jobPriority;
                printf("user_reorder_jobs->priority is %d\n", user_reorder_jobs->priority);
                user_reorder_jobs->result = malloc(sizeof(char)* 256);
                break;
        }
    }
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
    switch (operation_type)
    {
        case POLL :
            rc = ioctl(fd, POLL_OPS, (int32_t*) user_job_status);
            printf("user_job_status->result is %s\n", user_job_status->result);
            break;
        case STATUS :
            rc = ioctl(fd, STATUS_OPS, (int32_t*) user_job_status);
            break;
        case LIST :
            rc = ioctl(fd, LIST_OPS, (int32_t*) user_list_jobs);
            printf("user_list_jobs->result is %s\n", user_list_jobs->result);
            break;
        case DELETE :
            rc = ioctl(fd, DELETE_OPS, (int32_t*) user_job_status);
            break;
        case REORDER :
            printf("jobPriority %d\n",jobPriority);
            rc = ioctl(fd, REORDER_OPS, (int32_t*) user_reorder_jobs);
            printf("user_reorder_status->result is %s\n", user_reorder_jobs->result);
            break;
        default:    
            printf("No option specified\n");
    }
    
    printf("Closing Driver\n");
    printf("rs is %d\n",rc);
    printf("jobPriority is %d\n",jobPriority);
    close(fd); 
    if(user_job_status && user_job_status->result)
        free(user_job_status->result);
    if(user_list_jobs && user_list_jobs->result)
        free(user_list_jobs->result);
    if(user_job_status)
        free(user_job_status);
    if(user_list_jobs)
        free(user_list_jobs);
    if(user_reorder_jobs && user_reorder_jobs->result)
        free(user_reorder_jobs->result);
    if(user_reorder_jobs)
        free(user_reorder_jobs);
    
    return 0;
    
}