#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h> 
#include<linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/hashtable.h>

#include "file_operations.h"

#define NEW_TASK _IOW('a','a',int32_t*)
#define RD_VALUE _IOR('a','b',int32_t*)

#define POLL_OPS _IOW('a','c',int32_t*)
#define STATUS_OPS _IOW('a','d',int32_t*)
#define LIST_OPS _IOW('a','e',int32_t*)
#define REORDER_OPS _IOW('a','g',int32_t*)
#define DELETE_OPS _IOW('a','h',int32_t*)

#define DEFAULT_DELAY 5000
#define MAX_INMEM_JOBS_BITS 5
#define MAX_PENDING_JOBS 7
#define MAX_RUNNING_JOBS 7
#define MAX_INMEM_COMPLETED_JOBS 7
#define MAX_PATH_LEN 256

DEFINE_HASHTABLE(job_struct_ht, MAX_INMEM_JOBS_BITS);

static atomic_t global_jobid =  ATOMIC_INIT(1);
static atomic_t npending = ATOMIC_INIT(0);
static atomic_t nrunning = ATOMIC_INIT(0);
// static atomic_t ncompleted = ATOMIC_INIT(0);


struct workqueue_struct *wq = NULL;
struct workqueue_struct *highpri_wq = NULL;

struct delayed_work_struct {
    struct delayed_work dwork;
    int subtask_index;
    struct job_struct * main_task_js;
};

struct job_struct_ht_node {
    struct hlist_node hash;
    struct job_struct * js;
    int nodeid;
};

int32_t value = 0;

dev_t dev = 0;
static struct class *dev_class;
static struct cdev etx_cdev;

/*
** Function Prototypes
*/
static int      __init etx_driver_init(void);
static void     __exit etx_driver_exit(void);
static int      etx_open(struct inode *inode, struct file *file);
static int      etx_release(struct inode *inode, struct file *file);
static ssize_t  etx_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t  etx_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long     etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/*
** File operation sturcture
*/
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = etx_read,
        .write          = etx_write,
        .open           = etx_open,
        .unlocked_ioctl = etx_ioctl,
        .release        = etx_release,
};

/*
** DeAllocate Memory of a job structure
*/


void deallocate_job_struct_mem(struct job_struct * js)
{
        int i = 0;
        if(js == NULL) {
                return;
        }
        printk("deallocate_job_struct_mem for %d", js->jobid);

        for(;i < js->input_files_count;++i) {
                if(js->input_files && js->input_files[i]) {
                        kfree(js->input_files[i]);
                }
        }

        i = 0;
        for(;i < js->subtask_count;++i) {
                if(js->output_files && js->output_files[i]) {
                        kfree(js->output_files[i]);
                }
                if(js->subtask_delayed_work_structs && js->subtask_delayed_work_structs[i]) {
                        kfree(js->subtask_delayed_work_structs[i]);
                }
        }

        if(js->enc_key) {
                kfree(js->enc_key);
        }

        if(js->subtask_status) {
                kfree(js->subtask_status);
        }
        if(js->result_file) {
                kfree(js->result_file);
        }
       
        kfree(js);
}

/*
** -------------Work Queue operations start ---------------------
*/

static void work_handler(struct work_struct *work)
{
        // struct work_data * wdata = container_of(work, struct work_data, work);
        int status = 0;
        struct job_struct * js = NULL;
        struct delayed_work_struct *ws = container_of(work, struct delayed_work_struct, dwork.work);

        js = ws->main_task_js;
        printk("Inside work handler of id %d and subtask is %d", js->jobid, ws->subtask_index);

        /* Update status to running */
        js->subtask_status[ws->subtask_index] = (int) RUNNING;
        atomic_dec(&npending);
        atomic_inc(&nrunning);

        switch (ws->main_task_js->job_type){
                case ENCRYPT_FILE:
                        if(js->input_files && js->input_files[ws->subtask_index] && js->output_files && js->output_files[ws->subtask_index]) {
                                status = enc_dec(js->input_files[ws->subtask_index], js->output_files[ws->subtask_index], js->enc_key, 1);
                        } else {
                                status = -EINVAL;
                        }
                        break;
                case DECRYPT_FILE:
                        if(js->input_files && js->input_files[ws->subtask_index] && js->output_files && js->output_files[ws->subtask_index]) {
                                status = enc_dec(js->input_files[ws->subtask_index], js->output_files[ws->subtask_index], js->enc_key, 0);
                        } else {
                                status = -EINVAL;
                        }
                        break;
                case RENAME_FILES:
                        if(js->input_files && js->input_files[ws->subtask_index] && js->output_files && js->output_files[ws->subtask_index]) {
                                status = rename_file(js->input_files[ws->subtask_index], js->output_files[ws->subtask_index]);
                        } else {
                                status = -EINVAL;
                        }
                        break;
                case DELETE_FILES:
                        if(js->input_files && js->input_files[ws->subtask_index]) {
                                status = delete_file(js->input_files[ws->subtask_index]);
                        } else {
                                status = -EINVAL;
                        }
                        break;
                case CONCATANATE_FILES:
                        if(js->input_files && js->output_files && js->output_files[ws->subtask_index]) {
                                status = concatenate_files(js->input_files, js->input_files_count, js->output_files[ws->subtask_index]);
                        } else {
                                status = -EINVAL;
                        }
                        break;
                default:
                        break;
        }

       
        msleep(1000 + 200 * ws->subtask_index);
        
        atomic_dec(&nrunning);
        /* Update status to completed */
        js->subtask_status[ws->subtask_index] = (int) COMPLETED;
        printk("FINAL STATUS : %d\n", status);

        if(js->result_file) {
                //job completed write to the file
                if(main_task_completed(js)) {
                        write_js_results_to_file(js);
                }
        }

        js->subtask_delayed_work_structs[ws->subtask_index] = NULL;
        if(ws) {
                kfree(ws);
        }

        
}

void enqueue_job_into_wq(struct job_struct * js, int delay)
{
        int i = 0;
        struct delayed_work_struct * dw_struct = NULL;
        for(;i < js->subtask_count;++i) {
                if(atomic_read(&npending) + atomic_read(&nrunning) < MAX_PENDING_JOBS + MAX_RUNNING_JOBS) {
                        atomic_inc(&npending);
                        dw_struct = (struct delayed_work_struct *) js->subtask_delayed_work_structs[i];
                        INIT_DELAYED_WORK(&dw_struct->dwork, work_handler);
                        if(js->job_priority == 0) {
                                queue_delayed_work(wq, &dw_struct->dwork, msecs_to_jiffies(delay));
                        } else {
                                queue_delayed_work(highpri_wq, &dw_struct->dwork, msecs_to_jiffies(delay));
                        }
                } else {
                        js->subtask_status[i] = CANCELLED;
                }
                
        }
}

void move_job_to_target_wq(struct job_struct * js, struct workqueue_struct * target_wq, int mdelay, char * result)
{
        struct delayed_work_struct * dw_struct = NULL;
        int i = 0;

        strcat(result, "[ ");

        for(;i < js->subtask_count;++i) {
                dw_struct = (struct delayed_work_struct *) js->subtask_delayed_work_structs[i];
                if(!dw_struct)  {
                        strcat(result, "NOT_IN_Q"); 
                } else {
                        if(delayed_work_pending(&dw_struct->dwork) && js->subtask_status[i] != RUNNING) {
                                cancel_delayed_work_sync(&dw_struct->dwork);
                                queue_delayed_work(target_wq, &dw_struct->dwork, msecs_to_jiffies(mdelay));
                                strcat(result, "REORDERED");
                        }
                        else {
                                if(js->subtask_status[i] == RUNNING) {
                                        strcat(result, "BUSY");
                                } else {
                                        strcat(result, "NOT_IN_Q"); 
                                }
                        }
                }
                

                if (i+1 == js->subtask_count) {
                        strcat(result, " ]");
                } else {
                        strcat(result, ", ");
                }
        }
}


void cancel_work_from_wq(struct job_struct * js, char * result)
{
        struct delayed_work_struct * dw_struct = NULL;
        int i = 0;

        strcat(result, "[ ");

        for(;i < js->subtask_count;++i) {
                dw_struct = (struct delayed_work_struct *) js->subtask_delayed_work_structs[i];
                if(!dw_struct)  {
                        strcat(result, "NOT_IN_Q"); 
                } else {
                        if(delayed_work_pending(&dw_struct->dwork) && js->subtask_status[i] != RUNNING) {
                                cancel_delayed_work_sync(&dw_struct->dwork);
                                strcat(result, "DELETED");
                                js->subtask_status[i] = DELETED;
                        }
                        else {
                                if(js->subtask_status[i] == RUNNING) {
                                        strcat(result, "BUSY");
                                } else {
                                        strcat(result, "NOT_IN_Q"); 
                                }
                        }
                }
                

                if (i+1 == js->subtask_count) {
                        strcat(result, " ]");
                } else {
                        strcat(result, ", ");
                }
        }
}
// void sleep_time(int t) {
//         msleep(t);
// }


/*
** ------------- Work Queue operations End ---------------------
*/



/*
** ------------- Hash Table operations start ---------------------
*/

int add_job_to_ht(struct job_struct * js)
{
        int err = 1;
        struct job_struct_ht_node * jsht_node = NULL;
        printk("Inisde add_job_to_ht for %d", js->jobid);
        if(js->jobid == 1) {
                hash_init(job_struct_ht);
        }
        jsht_node = kmalloc(sizeof (struct job_struct_ht_node), GFP_ATOMIC);
        if(!jsht_node) {
                return -ENOMEM;
        }
        jsht_node->js = js;
        jsht_node->nodeid = js->jobid;
        hash_add(job_struct_ht, &jsht_node->hash, js->jobid);
        return err;
}

struct job_struct * get_js_from_ht(int jobid) {
        struct job_struct * js = NULL;
        struct job_struct_ht_node * jsht_node;
        hash_for_each_possible(job_struct_ht, jsht_node, hash, jobid)
        {
                if(jsht_node->nodeid != jobid) {
                        continue;
                }
                js = jsht_node->js;
        }
        return js;
}

void remove_job_from_ht(int jobid)
{
        struct job_struct * js = NULL;
        struct job_struct_ht_node * jsht_node;

        printk("Inisde remove_job_from_ht for %d", jobid);
        hash_for_each_possible(job_struct_ht, jsht_node, hash, jobid)
        {
                if(jsht_node->nodeid != jobid) {
                        continue;
                }
                hash_del(&jsht_node->hash);
                js = jsht_node->js;
                kfree(jsht_node);
        }

        if(js) {
                deallocate_job_struct_mem(js);
        }

}

void remove_all_job_from_ht(void)
{
        int low = 1;
        int high = 1;
        
        printk("Inside remove_all_job_from_ht \n");
        high = (int) atomic_read(&global_jobid);;

        while(low < high) {
                remove_job_from_ht(low);
                ++low;
        }
}


/*
** ------------- Hash Table operations end ---------------------
*/




/*
** Constructing and Allocating Memory to Structutres
*/

int get_subtask_count(struct __user_job_struct * uj_struct)
{
        if(uj_struct->input_files_count > 0 && (uj_struct->job_type == RENAME_FILES || uj_struct->job_type == DELETE_FILES || uj_struct->job_type == STAT_FILES)) {
                return uj_struct->input_files_count;
        } else {
                return 1;
        }
}


void construct_listall_jobs_res(char * result, int uid)
{
        char * jobidstr = NULL;
        struct job_struct_ht_node * jsht_node;
        int bkt;
        jobidstr = kmalloc(5, GFP_ATOMIC);

        hash_for_each(job_struct_ht, bkt, jsht_node, hash)
        {
                if(jsht_node && jsht_node->js && jsht_node->js->uid == uid) {
                        sprintf(jobidstr, "%5d", jsht_node->js->jobid); 
                        strcat(result, jobidstr);
                        strcat(result, "\t");

                        append_job_type_str(result, jsht_node->js);
                        strcat(result, "\t");

                        construct_job_status_res(result, jsht_node->js);
                        strcat(result, "\n");
                }
        }

        if(jobidstr) {
                kfree(jobidstr);
        }
}

int construct_job_struct(struct __user_job_struct * uj_struct)
{
        int ret = 0;

        struct job_struct * js = NULL;
        struct delayed_work_struct * dw_struct = NULL;

        int i = 0;
        printk("Inisde construct_job_struct ");

        js = kmalloc(sizeof(struct job_struct), GFP_ATOMIC);
        if(!js) {
                ret = -ENOMEM;
                printk("No mem for js");
                goto construct_js_out;
        }

        js->subtask_delayed_work_structs = NULL;
        js->enc_key = NULL;

        js->jobid = (int) atomic_read(&global_jobid);
        atomic_inc(&global_jobid);

        js->uid = uj_struct->uid;

        js->job_type = uj_struct->job_type;
        js->job_priority = uj_struct->priority;
        if(js->job_priority != 0 || js->job_priority != 1) {
                js->job_priority = 0;
        }

        js->subtask_count = get_subtask_count(uj_struct);

        if(uj_struct->key != NULL && access_ok(uj_struct->key, MD5_HASH_LENGTH)) {
                js->enc_key = kmalloc(sizeof(char) * MD5_HASH_LENGTH, GFP_ATOMIC);
                if(!js->enc_key) {
                        ret = -ENOMEM;
                        goto construct_js_out;
                }
                if(copy_from_user(js->enc_key, uj_struct->key, MD5_HASH_LENGTH)) {
                        ret = -EINVAL;
                        goto construct_js_out;
                }
        }

        js->input_files_count = uj_struct->input_files_count;
        if(js->input_files_count > 0) {
                js->input_files = kmalloc(sizeof(char *) * uj_struct->input_files_count, GFP_ATOMIC);
                if(!js->input_files) {
                        ret = -ENOMEM;
                        goto construct_js_out;
                }
        } else {
                js->input_files = NULL;
        }
        
        i = 0;
        for(;i < uj_struct->input_files_count;++i) {
                js->input_files[i] = NULL;
                if(!uj_struct->input_files || !uj_struct->input_files[i]) {
                        continue;
                }
                if(!access_ok(uj_struct->input_files[i]->filename, uj_struct->input_files[i]->len)) {
                        continue;
                }
                js->input_files[i] = kmalloc((1 + uj_struct->input_files[i]->len) * sizeof(char), GFP_ATOMIC);
                if(!js->input_files[i]) {
                        ret = -ENOMEM;
                        goto construct_js_out;
                }
                strcpy(js->input_files[i], uj_struct->input_files[i]->filename);
                strcat(js->input_files[i], "\0");
                printk("received inp file %d value = %s",i, js->input_files[i]);
        }

        if(uj_struct->output_files_count > 0) {
                js->output_files = kmalloc(sizeof(char *) * uj_struct->output_files_count, GFP_ATOMIC);
                if(!js->output_files) {
                        ret = -ENOMEM;
                        goto construct_js_out;
                }
        } else {
                js->output_files = NULL;
        }
        
        i = 0;
        for(;i < uj_struct->output_files_count;++i) {
                js->output_files[i] = NULL;
                if(!uj_struct->output_files || !uj_struct->output_files[i]) {
                        continue;
                }
                if(!access_ok(uj_struct->output_files[i]->filename, uj_struct->output_files[i]->len)) {
                        continue;
                }
                js->output_files[i] = kmalloc((1 + uj_struct->output_files[i]->len) * sizeof(char), GFP_ATOMIC);
                if(!js->output_files[i]) {
                        ret = -ENOMEM;
                        goto construct_js_out;
                }
                strcpy(js->output_files[i], uj_struct->output_files[i]->filename);
                strcat(js->output_files[i], "\0");
                printk("received out file %d value = %s",i, js->output_files[i]);
        }

        js->subtask_delayed_work_structs = kmalloc(js->subtask_count * sizeof(struct delayed_work_struct *), GFP_ATOMIC);
        if(!js->subtask_delayed_work_structs) {
                ret = -ENOMEM;
                goto construct_js_out;
        }
        i = 0;
        for(;i < js->subtask_count;++i) {
                dw_struct = kmalloc(sizeof(struct delayed_work_struct), GFP_ATOMIC);
                if(!dw_struct) {
                        ret = -ENOMEM;
                        goto construct_js_out;  
                }
                dw_struct->subtask_index = i;
                dw_struct->main_task_js = js;
                js->subtask_delayed_work_structs[i] = (void *) dw_struct;
        }

        js->subtask_status = kmalloc(js->subtask_count * sizeof(int), GFP_ATOMIC);
        if(!js->subtask_status) {
                ret = -ENOMEM;
                goto construct_js_out; 
        }
        i = 0;
        for(;i < js->subtask_count;++i) {
                js->subtask_status[i] = (int) PENDING;
        }

        js->result_file = NULL;

        if(uj_struct->result_file && access_ok(uj_struct->result_file->filename, uj_struct->result_file->len)) {
                js->result_file = kmalloc((1 + uj_struct->result_file->len) * sizeof(char), GFP_ATOMIC);
                if(!js->result_file) {
                        ret = -ENOMEM;
                        goto construct_js_out;
                }
                strcpy(js->result_file, uj_struct->result_file->filename);
                strcat(js->result_file,"\0");
                printk("received result file %d value = %s",i, js->result_file);
        }

        ret = add_job_to_ht(js);
        enqueue_job_into_wq(js, DEFAULT_DELAY);
        ret = js->jobid;
construct_js_out:
        if(ret <= 0 && js) {
                kfree(js);
        }
        return ret;
}




/*
** This function will be called when we open the Device file
*/

static int etx_open(struct inode *inode, struct file *file)
{
        pr_info("Device File Opened...!!!\n");
        /*Creating workqueue */
        wq = create_workqueue("hw3_wq");
        if(!wq) {
             printk("Unable to create workqueue");
        }
        highpri_wq =  alloc_workqueue("hw3_highpri_wq", WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_CPU_INTENSIVE, 0);
        if(!highpri_wq) {
             printk("Unable to create highpriority workqueue");
        }
        return 0;
}

/*
** This function will be called when we close the Device file
*/
static int etx_release(struct inode *inode, struct file *file)
{ 
        pr_info("Device File Closed...!!!\n");
        return 0;
}

/*
** This function will be called when we read the Device file
*/
static ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        pr_info("Read Function\n");
        return 0;
}

/*
** This function will be called when we write the Device file
*/
static ssize_t etx_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        pr_info("Write function\n");
        return len;
}

/*
** This function will be called when we write IOCTL on the Device file
*/
static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long argp)
{
        int ret = 0;
        struct __user_job_struct * uj_struct = NULL;
        char * result = NULL;
        struct job_struct *js = NULL;
        struct __user_job_status * uj_status = NULL;
        struct __user_list_jobs * ljobs = NULL;
        struct __user_reorder_job * rjob = NULL;
        void __user *arg_user;
        struct __user_delete_job * ud_job = NULL;
        arg_user = (void __user *)argp;
        
        printk("Started");
         switch(cmd) {
                case NEW_TASK:
                        uj_struct = kmalloc(sizeof (struct __user_job_struct), GFP_ATOMIC);
                        if(!uj_struct) {
                                ret = -ENOMEM;
                                printk("No mem for uj_struct");
                                goto ioctl_out;
                        }
                        if(copy_from_user(uj_struct, arg_user, sizeof(struct __user_job_struct))) {
                                printk("User Struct Copy Error");
                                goto ioctl_out;
                        }
                        ret = construct_job_struct(uj_struct);
                        printk("ID = %d\n", ret);
                        break;
                case POLL_OPS:
                        uj_status = kmalloc(sizeof (struct __user_job_status), GFP_ATOMIC);
                        if(!uj_status) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        if(copy_from_user(uj_status, arg_user, sizeof(struct __user_job_status))) {
                                printk("User Struct Copy Error");
                                ret = -EINVAL;
                                goto ioctl_out;
                        }
                        if(!uj_status->jobid || !uj_status->result || !uj_status->uid) {
                                ret = -EINVAL;
                                printk("Error invalid arguments");
                                break;
                        }
                        js = get_js_from_ht(uj_status->jobid);
                        if(js == NULL) {
                                printk("No Matching JOBID in HT");
                                ret = -EINVAL;;
                                break;
                        }
                        if(uj_status->uid != js->uid) {
                                ret = -EPERM;
                                printk("Error invalid arguments");
                                break;
                        }

                        result = kmalloc(sizeof(char) * 15 *js->subtask_count, GFP_ATOMIC);
                        if(!result) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        strcpy(result,"");
                        construct_job_status_res(result, js);
                        strcat(result, "\0");
                        ret = copy_to_user(uj_status->result, result, strlen(result));
                        break;
                case LIST_OPS:
                        ljobs = kmalloc(sizeof (struct __user_list_jobs), GFP_ATOMIC);
                        if(ljobs) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        if(copy_from_user(ljobs, arg_user, sizeof(struct __user_list_jobs))) {
                                printk("User Struct Copy Error");
                                ret = -EINVAL;
                                goto ioctl_out;
                        }
                        if(!ljobs->result || !ljobs->uid) {
                                ret = -EINVAL;
                                printk("Error invalid arguments");
                                break;
                        }
                        result = kmalloc(sizeof(char) * 2048, GFP_ATOMIC);
                        if(!result) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        strcpy(result,"\n");
                        construct_listall_jobs_res(result, ljobs->uid);
                        strcat(result, "\0");
                        ret = copy_to_user(ljobs->result, result, strlen(result));
                        break;
                case REORDER_OPS:
                        rjob = kmalloc(sizeof (struct __user_reorder_job), GFP_ATOMIC);
                        if(!rjob) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        if(copy_from_user(rjob, arg_user, sizeof(struct __user_reorder_job))) {
                                printk("User Struct Copy Error");
                                ret = -EINVAL;
                                goto ioctl_out;
                        }
                        if(!rjob->jobid || !rjob->result || !rjob->uid || (rjob->priority != 0 && rjob->priority != 1)) {
                                ret = -EINVAL;
                                printk("Error invalid arguments");
                                break;
                        }
                        js = get_js_from_ht(rjob->jobid);
                        if(js == NULL) {
                                printk("No Matching JOBID in HT");
                                ret = -EINVAL;;
                                break;
                        }

                        if(rjob->uid != js->uid) {
                                ret = -EPERM;
                                printk("Error invalid arguments");
                                break;
                        }
                        result = kmalloc(sizeof(char) * 15 *js->subtask_count, GFP_ATOMIC);
                        if(!result) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        strcpy(result,"\n");
                        printk("reorder priorities inc: %d present: %d", rjob->priority, js->job_priority);
                        if(rjob->priority > js->job_priority) {
                                move_job_to_target_wq(js, highpri_wq, 0, result);
                        } else if (rjob->priority < js->job_priority){
                                move_job_to_target_wq(js, wq, DEFAULT_DELAY, result);
                        } else {
                                printk("Already queued in the same priority\n");
                                ret = -EINVAL;
                                goto ioctl_out;
                        }
                        strcat(result, "\0");
                        ret = copy_to_user(rjob->result, result, strlen(result));
                        break;
                case DELETE_OPS:
                        ud_job = kmalloc(sizeof (struct __user_delete_job), GFP_ATOMIC);
                        if(!ud_job) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        if(copy_from_user(ud_job, arg_user, sizeof(struct __user_delete_job))) {
                                printk("User Struct Copy Error");
                                ret = -EINVAL;
                                goto ioctl_out;
                        }
                        if(!ud_job->jobid || !ud_job->result || !ud_job->uid) {
                                ret = -EINVAL;
                                printk("Error invalid arguments");
                                break;
                        }
                        js = get_js_from_ht(ud_job->jobid);
                        if(js == NULL) {
                                printk("No Matching JOBID in HT");
                                ret = -EINVAL;;
                                break;
                        }
                        if(ud_job->uid != js->uid) {
                                ret = -EPERM;
                                printk("Error invalid arguments");
                                break;
                        }
                        result = kmalloc(sizeof(char) * 15 *js->subtask_count, GFP_ATOMIC);
                        if(!result) {
                                ret = -ENOMEM;
                                printk("No mem for uj_status");
                                break;
                        }
                        strcpy(result,"\n");
                        cancel_work_from_wq(js, result);
                        strcat(result, "\0");
                        ret = copy_to_user(ud_job->result, result, strlen(result));
                        break;

                default:
                        pr_info("Default\n");
                        break;
        }

ioctl_out:
        if(uj_struct) {
                kfree(uj_struct);
        }
        if(uj_status) {
                kfree(uj_status);
        }
        if(rjob) {
                kfree(rjob);
        }
        if(ud_job) {
                kfree(ud_job);
        }
        if(result) {
                kfree(result);
        }

        return ret;
}
 
/*
** Module Init function
*/
static int __init etx_driver_init(void)
{
        /*Allocating Major number*/
        if((alloc_chrdev_region(&dev, 0, 1, "etx_Dev")) <0){
                pr_err("Cannot allocate major number\n");
                return -1;
        }
        pr_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));
 
        /*Creating cdev structure*/
        cdev_init(&etx_cdev,&fops);
 
        /*Adding character device to the system*/
        if((cdev_add(&etx_cdev,dev,1)) < 0){
            pr_err("Cannot add the device to the system\n");
            goto r_class;
        }
 
        /*Creating struct class*/
        if((dev_class = class_create(THIS_MODULE,"etx_class")) == NULL){
            pr_err("Cannot create the struct class\n");
            goto r_class;
        }
 
        /*Creating device*/
        if((device_create(dev_class,NULL,dev,NULL,"etx_device")) == NULL){
            pr_err("Cannot create the Device 1\n");
            goto r_device;
        }
        atomic_set(&global_jobid, 1);
        atomic_set(&npending, 0);
        atomic_set(&nrunning, 0);
        pr_info("Device Driver Insert...Done!!!\n");
        return 0;
r_device:
        class_destroy(dev_class);
r_class:
        unregister_chrdev_region(dev,1);
        return -1;
}

/*
** Module exit function
*/
static void __exit etx_driver_exit(void)
{
        
        if(wq) {
                flush_workqueue(wq);
                destroy_workqueue(wq);
        }
        
        if(highpri_wq) {
                flush_workqueue(highpri_wq);
                destroy_workqueue(highpri_wq);
        }

        remove_all_job_from_ht();
        
        device_destroy(dev_class,dev);
        class_destroy(dev_class);
        cdev_del(&etx_cdev);
        unregister_chrdev_region(dev, 1);
        pr_info("Device Driver Remove...Done!!!\n");
}

module_init(etx_driver_init);
module_exit(etx_driver_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vedhachala");
MODULE_DESCRIPTION("AsyncQueue");
MODULE_VERSION("1.5");