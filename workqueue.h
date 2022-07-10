typedef enum job_type{
    DELETE_FILES = 0,
    RENAME_FILES,
    STAT_FILES,
    CONCATANATE_FILES,
    COMPUTE_AND_RETURN_HASH_OF_A_FILE,
    ENCRYPT_FILE,
    DECRYPT_FILE,
    COMPRESS_FILE,
    DECOMPRESS_FILE
} job_type;

typedef enum job_status {
    PENDING,
    RUNNING,
    COMPLETED
} job_status;

struct file_details {
    char * filename;
    int len;
};

struct __user_job_struct {
    job_type job_type;
    int priority; // default to 0, optional 1

    struct file_details ** input_files;
    int input_files_count; // getname(input_files[])

    struct file_details ** output_files;
    int output_files_count;

    char *key;
    unsigned int key_length;
};

struct __user_job_status {
    int jobid;
    char * result;
};

struct __user_list_jobs {
    int timestamp;
    char * result;
};

struct __user_reorder_job {
    int jobid;
    int priority;
    char * result;
};