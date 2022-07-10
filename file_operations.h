
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "workqueue.h"

#define MAX_DIGEST_SIZE 64
#define MD5_HASH_LENGTH 16
#define MAX_HASH_FILE_SIZE 1048576

#define PLINE printk("line %d \n",20);


struct job_struct {
    int jobid;
    int uid;
    job_type job_type;
    int job_priority;

    char ** input_files;
    int input_files_count; // For concatenate number of input files is not subtask_count

    char ** output_files;
    int subtask_count; // same as number of output files for all operations

    char *enc_key;

    char * result_file;

    void ** subtask_delayed_work_structs; // size = subtask_count
    int * subtask_status; // size = subtask_count
};

struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};


void append_job_type_str(char * buffer, struct job_struct * js)
{
        switch(js->job_type) {
                case DELETE_FILES:
                        strcat(buffer, "DELETE_FILES");
                        break;
                case RENAME_FILES:
                        strcat(buffer, "RENAME_FILES");
                        break;
                case STAT_FILES:
                        strcat(buffer, "STAT_FILES");
                        break;
                case CONCATANATE_FILES:
                        strcat(buffer, "CONCATANATE_FILES");
                        break;
                case COMPUTE_AND_RETURN_HASH_OF_A_FILE:
                        strcat(buffer, "HASH_FILE");
                        break;
                case ENCRYPT_FILE:
                        strcat(buffer, "ENCRYPT_FILE");
                        break;
                case DECRYPT_FILE:
                        strcat(buffer, "DECRYPT_FILE");
                        break;
                case COMPRESS_FILE:
                        strcat(buffer, "COMPRESS_FILE");
                        break;
                case DECOMPRESS_FILE:
                        strcat(buffer, "DECOMPRESS_FILE");
                        break;
                default:
                        break;
        }
}

void construct_job_status_res(char * result, struct job_struct * js)
{
        int i = 0;
        char * status_num = NULL;
        
        status_num = kmalloc(sizeof(char) * 5, GFP_ATOMIC);
		if(!status_num) {
			return;
		}
        strcat(result, "[ ");
        
        for(;i < js->subtask_count;++i) {
                switch(js->subtask_status[i]) {
                case PENDING:
                        strcat(result, "PENDING");
                        break;
                case RUNNING:
                        strcat(result, "RUNNING");
                        break;
                case COMPLETED:
                        strcat(result, "COMPLETED");
                        break;
				case DELETED:
                        strcat(result, "DELETED");
                        break;
				case CANCELLED:
						strcat(result, "CANCELLED");
						break;
                default:
                        strcat(result, "ERR=");
                        sprintf(status_num, "%5d", js->subtask_status[i]);
                        strcat(result, status_num);
                        break;
                }
                if(i+1 == js->subtask_count) {
                        strcat(result, " ]");
                } else {
                        strcat(result, ", ");
                }
        }
        if(status_num) {
                kfree(status_num);
        }
}


void write_js_results_to_file(struct job_struct* js) 
{
	struct file * ofile = NULL;
	char * int_buf = NULL;
	char * file_buf = NULL;
	char * outputfilename = NULL;
	int i = 0;

	if(js->result_file) {
		outputfilename = js->result_file;
		js->result_file = NULL;
	}

	printk("Writing to File %s", outputfilename);
	if(!outputfilename) {
		goto write_file_cleanups;
	}
	ofile = filp_open(outputfilename, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if(IS_ERR(ofile)) {
		// err = PTR_ERR(ofile);
		printk("Error filpopen : outfile file");
		goto write_file_cleanups;
	}
	int_buf = kmalloc(sizeof(int), GFP_KERNEL);
	if(!int_buf) {
		printk("intbuf mem err");
		goto write_file_cleanups;
	}
	file_buf = kmalloc((PAGE_SIZE/2) * sizeof(char), GFP_KERNEL);
	if(!file_buf) {
		printk("intbuf mem err");
		goto write_file_cleanups;
	}
	
	sprintf(int_buf, "%d", js->jobid);
	strcpy(file_buf,"JOBID: ");
	strcat(file_buf, int_buf);
	strcat(file_buf, "\n");

	strcat(file_buf,"Operation: ");
	append_job_type_str(file_buf, js);
	strcat(file_buf, "\n");

	strcat(file_buf,"STATUS: ");
	construct_job_status_res(file_buf, js);
	strcat(file_buf, "\n");

	
	if(js->input_files && js->input_files_count > 0) {
		strcat(file_buf, "\nInput Files: \n");
		i = 0;
		for(;i < js->input_files_count;++i) {
			strcat(file_buf, js->input_files[i]);
			strcat(file_buf, "\n");
		}
	}

	if(js->output_files && js->subtask_count > 0) {
		strcat(file_buf, "\nOutput Files: \n");
		i = 0;
		for(;i < js->subtask_count;++i) {
			strcat(file_buf, js->output_files[i]);
			strcat(file_buf, "\n");
		}
	}
	
	printk("Writing Results to File %s", outputfilename);
	kernel_write(ofile, file_buf, strlen(file_buf), &(ofile->f_pos));

write_file_cleanups:
	if(ofile != NULL && !IS_ERR(ofile)) {
		filp_close(ofile, NULL);
	}


	if(int_buf) {
		kfree(file_buf);
	}

	if(file_buf) {
		kfree(file_buf);
	}

}

int main_task_completed(struct job_struct * js) 
{
	int ret = 1;
	int i = 0;
	if(js->subtask_count > 0 && js->subtask_status) {
		for(;i < js->subtask_count;++i) {
			if(!js->subtask_status) {
				continue;
			}
			if(js->subtask_status[i] == RUNNING || js->subtask_status[i] == PENDING) {
				ret = 0;
				break;
			}
		}
	}
	return ret;
}




int compute_md5_hash(char *keybuf, char *hash) {
	struct scatterlist sg[2];
	struct ahash_request *req = NULL;
	struct crypto_ahash *tfm = NULL;
	int err =0;
	printk("Compting the hash");
	tfm = crypto_alloc_ahash("md5", CRYPTO_ALG_TYPE_SKCIPHER, CRYPTO_ALG_ASYNC);
	PLINE;
	if (IS_ERR(tfm)) {
		pr_err("error failed to load transform for md5: %ld\n", PTR_ERR(tfm));
		err =PTR_ERR(tfm);
		goto compute_md5_hash_out;
	}
	PLINE;
	if (crypto_ahash_digestsize(tfm) > MAX_DIGEST_SIZE) {
		pr_err("error digestsize(%u) > %d\n", crypto_ahash_digestsize(tfm),
		       MAX_DIGEST_SIZE);
		goto compute_md5_hash_out;
	}
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("error ahash request allocation failure\n");
		err =-ENOMEM;
		goto compute_md5_hash_out;
	}
	PLINE;
	sg_init_one(sg, keybuf, strlen(keybuf));
	PLINE;
	ahash_request_set_callback(req, 0, NULL, NULL);
	PLINE;
	ahash_request_set_crypt(req, sg, hash, 16);
	PLINE;
	if(crypto_ahash_digest(req) != 0) {
		pr_err("error Error while calculating digest\n");
		err =-EFAULT;
		goto compute_md5_hash_out;
	}
	PLINE;
compute_md5_hash_out:
	if(tfm) {
		crypto_free_ahash(tfm);
	}
	if(req) {
		ahash_request_free(req);
	}
	printk("err in compute hash is %d\n",err);
	return err;
}

int compute_md5_hash_vedha(char *keybuf, char *hash) {
	struct scatterlist sg[1];
	struct ahash_request *req = NULL;
	struct crypto_ahash *tfm = NULL;
	int ret = 0;

	tfm = crypto_alloc_ahash("md5", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("error failed to load transform for md5: %ld\n", PTR_ERR(tfm));
		ret = PTR_ERR(tfm);
		goto compute_md5_hash_out;
	}
	if (crypto_ahash_digestsize(tfm) > MAX_DIGEST_SIZE) {
		pr_err("error digestsize(%u) > %d\n", crypto_ahash_digestsize(tfm),
		       MAX_DIGEST_SIZE);
		goto compute_md5_hash_out;
	}
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("error ahash request allocation failure\n");
		ret = -ENOMEM;
		goto compute_md5_hash_out;
	}
	sg_init_one(&sg[0], keybuf, 16);
	ahash_request_set_callback(req, 0, NULL, NULL);
	ahash_request_set_crypt(req, sg, hash, 16);
	if(crypto_ahash_digest(req) != 0) {
		pr_err("error Error while calculating digest\n");
		ret = -EFAULT;
		goto compute_md5_hash_out;
	}
	hash[16] = '\0';
	compute_md5_hash_out:
	if(tfm) {
		crypto_free_ahash(tfm);
	}
	if(req) {
		ahash_request_free(req);
	}
	return ret;
}


int hashFile(char * inputfilename)
{
    int err =0;
	struct file * ifile = NULL;
	struct file * hash_ofile = NULL;
    struct dentry * ifile_dentry = NULL;
	char * file_buffer = NULL, *outputfilename = NULL;
	char * hash_buffer = NULL, *hash_temp_buffer = NULL;
	char * hash_ofile_path = NULL; //* ofile_path;
	unsigned int total_file_size = 0, number_of_reads = 0, read_count = 0, iter_count = 0, write_count = 0, read_size = 0;
	printk("In enc dec hash...\n");

	outputfilename = kmalloc((strlen(inputfilename) + 10) * sizeof(char), GFP_KERNEL);
	strcpy(outputfilename, inputfilename);
	strcat(outputfilename, ".hashed\0");
    printk("in enc_dec inputfile %s", inputfilename);
    printk("in enc_dec outputfile %s", outputfilename);

    ifile = filp_open(inputfilename, O_RDONLY, 0);
	if(IS_ERR(ifile)) {
		printk("error filpopen: input file");
		goto file_cleanups;
	}

    ifile_dentry = ifile->f_path.dentry;

	file_buffer = (char *) kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if(file_buffer == NULL) {
		err =-ENOMEM;
		printk("Error kmalloc");
		goto file_cleanups;
	}
	printk("allocating buffer each page hash");
	hash_temp_buffer = kmalloc(sizeof(char)*17, GFP_KERNEL);
	if(hash_temp_buffer == NULL) {
		err =-ENOMEM;
		printk("Error kmalloc hash_buffer");
		goto file_cleanups;
	}
	total_file_size = ifile_dentry->d_inode->i_size;

	if(total_file_size > MAX_HASH_FILE_SIZE){
		printk("File size is more for hashing");
		err =-EFBIG;
		goto file_cleanups;
	}

	number_of_reads = (total_file_size + PAGE_SIZE - 1) / PAGE_SIZE;

	hash_buffer = kmalloc(( sizeof(char) * number_of_reads * 16) + 1 , GFP_KERNEL);
	printk("allocating buffer for overall hash");
	if(hash_buffer == NULL) {
		err =-ENOMEM;
		printk("Error kmalloc hash_buffer");
		goto file_cleanups;
	}
	memset(hash_buffer, 0, ( sizeof(char) * number_of_reads * 16) + 1);
	// ifile->f_pos = 0;
	for(;iter_count < number_of_reads;iter_count ++) {
		if(iter_count == number_of_reads - 1 && (total_file_size%PAGE_SIZE) > 0) {
			read_size = total_file_size % PAGE_SIZE;
		} else {
			read_size = PAGE_SIZE;
		}
		printk("read_size is %d\n", read_size);
		read_count = kernel_read(ifile, file_buffer, read_size, &(ifile->f_pos));
		printk("read_count %d\n",read_count);
		if(read_count != read_size) {
			err =-EFAULT;
			printk("Error buffer reading");
			goto file_cleanups;
		}
		err =compute_md5_hash(file_buffer, hash_temp_buffer);
		if(err) {
			err =-EFAULT;
			printk("err while hashing");
			goto file_cleanups;
		}
		printk("copying hash temp buff to hash buf so we can use temp buff to cal actual hash");
		strcat(hash_buffer, hash_temp_buffer);
	}
	memset(hash_temp_buffer, 0 ,16);
	hash_buffer[strlen(hash_buffer)] = '\0';
	read_size = sizeof(hash_buffer);
	hash_ofile_path = kmalloc(256, GFP_KERNEL);
	strcpy(hash_ofile_path, inputfilename);
	strcat(hash_ofile_path, ".hashed\0");

	hash_ofile = filp_open(hash_ofile_path, O_WRONLY | O_TRUNC | O_CREAT, 0644);

	if(IS_ERR(hash_ofile)) {
		err =PTR_ERR(hash_ofile);
		printk("Error filpopen : hash outfile file");
		goto file_cleanups;
	}

	err =compute_md5_hash(hash_buffer, hash_temp_buffer);
	hash_temp_buffer[16] = '\0';
	if(err) {
		err =-EFAULT;
		printk("err while hashing");
		goto file_cleanups;
	}

	write_count = kernel_write(hash_ofile, hash_temp_buffer, MD5_HASH_LENGTH, 0);
	if(write_count != read_size) {
		err =-EFAULT;
		printk("error buffer writing err");
		goto file_cleanups;
	}
	if(err == 0)
		printk("Successfully implements the operation");

file_cleanups:

	if(hash_buffer){
		kfree(hash_buffer);
	}
	if(hash_temp_buffer)
		kfree(hash_temp_buffer);
    if(file_buffer) {
        kfree(file_buffer);
    }
    if(ifile != NULL && !IS_ERR(ifile)) {   
		filp_close(ifile, NULL);
	}
	if(hash_ofile != NULL && !IS_ERR(hash_ofile)) {
		filp_close(hash_ofile, NULL);
	}
	if(outputfilename){
		kfree(outputfilename);
	}
    return err;
}

/*
Referrence: https://www.kernel.org/doc/html/v5.2/crypto/api-samples.html (Code Example for symmetric ciphers)
functions is declared globally (as extern uint) to be used modularly from other places to enc/dec
*/
unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc) {
    int rc = 0;
    if (enc == 1)
        rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
    else
        rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);
    if (rc)
            pr_err("error skcipher encrypt/decrypt returned with result %d\n", rc);
    return rc;
}

/*
Referrence: https://www.kernel.org/doc/html/v5.2/crypto/api-samples.html (Code Example for symmetric ciphers)
			https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html (Reading)
functions is declared globally (as extern int) to be used modularly from other places to enc/dec
*/
int test_skcipher(char *file_buffer,unsigned int byte_count, void *hash, int flag) {
	struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *ivdata = NULL;
    int ret = 0;

	skcipher = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        printk("could not allocate skcipher handle\n");
        ret = PTR_ERR(skcipher);
		goto test_skcipher_out;
    }

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        printk("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto test_skcipher_out;
    }

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      crypto_req_done,
                      &sk.wait);

	/* AES 128 - 16 */
    if (crypto_skcipher_setkey(skcipher, hash, MD5_HASH_LENGTH)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto test_skcipher_out;
    }

	ivdata = kmalloc(16, GFP_KERNEL);
	if (!ivdata) {
		ret = -ENOMEM;
		goto test_skcipher_out;
	}
	memcpy(ivdata, "vedhachalassssss", 16);

	sk.tfm = skcipher;
	sk.req = req;
	/* We encrypt one block */
    sg_init_one(&sk.sg, file_buffer, byte_count);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, byte_count, ivdata);
	crypto_init_wait(&sk.wait);
    ret = test_skcipher_encdec(&sk, flag);
    if (ret) {
		goto test_skcipher_out;
	}

	test_skcipher_out:
	if(skcipher) {
		crypto_free_skcipher(skcipher);
	}
	if(req) {
		skcipher_request_free(req);
	}
	if(ivdata != NULL) {
		kfree(ivdata);
	}
	return ret;
}

int rename_file(char * inputfilename, char * outputfilename)
{
	int err = 0;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = do_renameat2(AT_FDCWD, (const char *) inputfilename, AT_FDCWD, (const char *) outputfilename, 0);
	set_fs(oldfs);
	return err;
}


int delete_file(char * inputfilename)
{

	int err = 0;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = (int) do_unlinkat2((const char *) inputfilename);
	set_fs(oldfs);
	return err;
}

int checkInputFile(char *inputfilename)
{
	int err =0;
	struct kstat ks;
	mm_segment_t old_fs;
	struct filename *kinfile = NULL;
	kinfile = getname(inputfilename);
	if(IS_ERR(kinfile)){
		printk("error in getname\n");
		err =PTR_ERR(kinfile);
		goto inputfile_checks;
	}
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err =vfs_stat(inputfilename, &ks);
	set_fs(old_fs);
	if (err) {
		printk("incorrect file\n");
		err =-EBADF;
		goto inputfile_checks;
	} else if (S_ISDIR(ks.mode)) {
		printk("input file is a directory\n");
		err =-EISDIR;
		goto inputfile_checks;
	} else if (!(ks.mode & S_IRUSR)) {
		printk("no permissions for reading\n");
		err =-EACCES;
		goto inputfile_checks;
	} else if (!(S_ISREG(ks.mode))) {
		printk("File is not regular\n");
		err =-EBADF;
		goto inputfile_checks;
	}
	printk("Inputfile checks done successfully");
inputfile_checks:
	if(kinfile)
		putname(kinfile);
	return err;
}

int checkoutfiles(char *outputfilename)
{
	int err =0;
	struct kstat ks;
	mm_segment_t old_fs;
	struct filename *koutfile = NULL;
	koutfile = getname(outputfilename);
	if(IS_ERR(koutfile)){
		printk("error in getname\n");
		err =PTR_ERR(koutfile);
		goto outputfile_checks;
	}
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err =vfs_stat(outputfilename, &ks);
	set_fs(old_fs);
	if (err < 0) {
		if (!(ks.mode & S_IWUSR)) {
			printk("user permissions are %d\n",ks.mode);
			printk("no access to write to the file\n");
			err =-EACCES;
			goto outputfile_checks;
		}
		if (!S_ISREG(ks.mode)) {
			printk("file is not Regular\n");
			err =-EBADF;
			goto outputfile_checks;
		}
	}
	if(S_ISDIR(ks.mode)) {
		printk("given file is a directory\n");
		return -EISDIR;
	}
	printk("outputfile checks done successfully");
outputfile_checks:
	if(koutfile)
		putname(koutfile);
	return err;
}

int statFile(char * inputfilename){
	struct kstat ks;
	char * result_buffer = NULL;
	char * result_file = NULL;
	struct file * stat_file = NULL;
	struct filename *kinfile = NULL;
	int err =0, write_count = 0;
	mm_segment_t oldfs;
	err = checkInputFile(inputfilename);
	if(err < 0){
		printk("error while checking input file properties. Please check for permissions");
		goto statfile_cleanups;
	}
	PLINE;
	kinfile = getname(inputfilename);
	if(IS_ERR(kinfile)){
		printk("error in getname\n");
		err =PTR_ERR(kinfile);
		goto statfile_cleanups;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err =vfs_stat(kinfile->name, &ks);
	if(err){
		err =-EBADF;
		printk("input file name incorrect\n");
		return err;
	}
	PLINE;
	set_fs(oldfs);
	result_buffer = kmalloc(PAGE_SIZE,GFP_KERNEL);
	printk("blocks is %lld\n", ks.blocks);
	sprintf(result_buffer, "Mode is %d\n UID is %d\n GID is %d\nblksize is %d\nblocks is %lld\n", ks.mode, ks.uid.val, ks.gid.val , ks.blksize ,ks.blocks);
	result_file = kmalloc(strlen(kinfile->name) + 6, GFP_KERNEL);
	strcpy(result_file, kinfile->name);
	strcat(result_file, ".stat");
	stat_file = filp_open(result_file, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if(IS_ERR(stat_file)) {
		err =PTR_ERR(stat_file);
		printk("Error in filp open");
		goto statfile_cleanups;
	}
	PLINE;
	// size = stat_file->f_path.dentry->d_inode->i_size;
	write_count = kernel_write(stat_file, result_buffer, strlen(result_buffer), &(stat_file->f_pos));
	if(write_count != strlen(result_buffer) ) {
		printk("write_count is %d\n",write_count);
		err =-EFAULT;
		printk("error buffer writing err");
		goto statfile_cleanups;
	}
statfile_cleanups:
	if(stat_file)
		filp_close(stat_file, NULL);
	if(result_file)
		kfree(result_file);
	if(result_buffer)
		kfree(result_buffer);
	if(kinfile)
		putname(kinfile);
	return err;
}


int enc_dec(char * inputfilename, char * outputfilename, char * enc_key, int enc_flag)
{
    int err = 0;
    struct file * ofile = NULL;
	struct file * ifile = NULL;
    struct dentry * ifile_dentry = NULL;
	char * file_buffer = NULL;
	struct filename * inputfile = NULL;
	struct filename * outputfile = NULL;
	unsigned int total_file_size = 0, number_of_reads = 0, read_count = 0, iter_count = 0, write_count = 0, read_size = 0;
    

    if(!inputfilename || !outputfilename || !enc_key) {
        err = -EINVAL;
        goto file_cleanups;
    }

    // inputfile = getname(inputfilename);
    // if(IS_ERR(inputfile)) {
    //     err = PTR_ERR(inputfile);
    //     goto file_cleanups;
    // }

    // outputfile = getname(outputfilename);
    // if(IS_ERR(outputfile)) {
    //     err = PTR_ERR(outputfile);
    //     goto file_cleanups;
    // }

    printk("in enc_dec inputfile %s", inputfilename);
    printk("in enc_dec outputfile %s", outputfilename);

    ifile = filp_open(inputfilename, O_RDONLY, 0);
	if(IS_ERR(ifile)) {
		printk("error filpopen: input file");
		goto file_cleanups;
	}

	ofile = filp_open(outputfilename, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if(IS_ERR(ofile)) {
		err = PTR_ERR(ofile);
		printk("Error filpopen : outfile file");
		goto file_cleanups;
	}

    ifile_dentry = ifile->f_path.dentry;

	file_buffer = (char *) kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if(file_buffer == NULL) {
		err = -ENOMEM;
		printk("Error kmalloc");
		goto file_cleanups;
	}

	total_file_size = ifile_dentry->d_inode->i_size;
	number_of_reads = (total_file_size + PAGE_SIZE - 1) / PAGE_SIZE;
	for(;iter_count < number_of_reads;iter_count ++) {
		if(iter_count == number_of_reads - 1 && (total_file_size%PAGE_SIZE) > 0) {
			read_size = total_file_size % PAGE_SIZE;
		} else {
			read_size = PAGE_SIZE;
		}

		read_count = kernel_read(ifile, file_buffer, read_size, &(ifile->f_pos));
		if(read_count != read_size) {
			err = -EFAULT;
			printk("Error buffer reading");
			goto file_cleanups;
		}
		err = test_skcipher(file_buffer, read_size, enc_key, enc_flag);
		if(err) {
			err = -EFAULT;
			printk("err while encrypt");
			goto file_cleanups;
		}
		write_count = kernel_write(ofile, file_buffer, read_size, &(ofile->f_pos));
		if(write_count != read_size) {
			err = -EFAULT;
			printk("error buffer writing err");
			goto file_cleanups;
		}
	}


file_cleanups:
    if(ifile != NULL && !IS_ERR(ifile)) {   
		filp_close(ifile, NULL);
	}
	if(ofile != NULL && !IS_ERR(ofile)) {
		filp_close(ofile, NULL);
	}

	if(inputfile && !IS_ERR(inputfile)) {
		putname(inputfile);
	}

	if(outputfile && !IS_ERR(outputfile)) {
		putname(outputfile);
	}

    if(file_buffer) {
        kfree(file_buffer);
    }
    return err;
}




int concatenate_files(char ** input_files, int input_files_count, char * outputfilename)
{
    int err = 0;
    struct file * ofile = NULL;
	struct file * ifile = NULL;
    struct dentry * ifile_dentry = NULL;
	char * file_buffer = NULL;
	int i = 0;
	int concat_corrupt = 0;
	unsigned int total_file_size = 0, number_of_reads = 0, read_count = 0, iter_count = 0, write_count = 0, read_size = 0;
    

    if(!outputfilename || !input_files) {
        err = -EINVAL;
        goto concat_file_cleanups;
    }

	ofile = filp_open(outputfilename, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if(IS_ERR(ofile)) {
		err = PTR_ERR(ofile);
		printk("Error filpopen : outfile file");
		goto concat_file_cleanups;
	}

	file_buffer = (char *) kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if(file_buffer == NULL) {
		err = -ENOMEM;
		printk("Error kmalloc");
		goto concat_file_cleanups;
	}

	for(;i < input_files_count;++i) {

		if(!input_files[i]) {
			err = -EINVAL;
			concat_corrupt = 1;
			goto concat_file_cleanups;
		}

		total_file_size = 0;
		number_of_reads = 0;
		read_count = 0;
		iter_count = 0;
		write_count = 0;
		read_size = 0;

		ifile = filp_open(input_files[i], O_RDONLY, 0);
		if(IS_ERR(ifile)) {
			printk("error filpopen: input file");
			concat_corrupt = 1;
			goto concat_file_cleanups;
		}
		ifile_dentry = ifile->f_path.dentry;

		total_file_size = ifile_dentry->d_inode->i_size;
		number_of_reads = (total_file_size + PAGE_SIZE - 1) / PAGE_SIZE;
		for(;iter_count < number_of_reads;iter_count ++) {
			if(iter_count == number_of_reads - 1 && (total_file_size%PAGE_SIZE) > 0) {
				read_size = total_file_size % PAGE_SIZE;
			} else {
				read_size = PAGE_SIZE;
			}

			read_count = kernel_read(ifile, file_buffer, read_size, &(ifile->f_pos));
			if(read_count != read_size) {
				err = -EFAULT;
				concat_corrupt = 1;
				printk("Error buffer reading");
				goto concat_file_cleanups;
			}
			write_count = kernel_write(ofile, file_buffer, read_size, &(ofile->f_pos));
			if(write_count != read_size) {
				err = -EFAULT;
				concat_corrupt = 1;
				printk("error buffer writing err");
				goto concat_file_cleanups;
			}
		}

		filp_close(ifile, NULL);
		ifile = NULL;
	}

concat_file_cleanups:
    if(ifile != NULL && !IS_ERR(ifile)) {   
		filp_close(ifile, NULL);
	}
	if(ofile != NULL && !IS_ERR(ofile)) {
		filp_close(ofile, NULL);
	}

    if(file_buffer) {
        kfree(file_buffer);
    }
	if(concat_corrupt) {
		printk("Deleting the partial file");
		// delete outputfile;
	}
    return err;
}