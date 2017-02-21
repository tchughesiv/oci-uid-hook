#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <libtar.h>
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>
#include <libmount/libmount.h>

#include "docker.h"
#include "config.h"

#define DOCKER_CONTAINER "docker"
#define ETC_PASSWD "/etc/passwd"

static unsigned long get_mem_total() {
	struct sysinfo info;
	int ret = sysinfo(&info);
	if (ret < 0) {
		return ret;
	}
	return info.totalram;
}

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void freep(void *p) {
	free(*(void**) p);
}

static inline void closep(int *fd) {
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static inline void fclosep(FILE **fp) {
	if (*fp)
		fclose(*fp);
	*fp = NULL;
}

static inline void mnt_free_iterp(struct libmnt_iter **itr) {
	if (*itr)
		mnt_free_iter(*itr);
	*itr=NULL;
}

static inline void mnt_free_fsp(struct libmnt_fs **itr) {
	if (*itr)
		mnt_free_fs(*itr);
	*itr=NULL;
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_mnt_iter_ _cleanup_(mnt_free_iterp)
#define _cleanup_mnt_fs_ _cleanup_(mnt_free_fsp)

#define DEFINE_CLEANUP_FUNC(type, func)            \
	static inline void func##p(type *p) {          \
		if (*p)                                    \
			func(*p);                              \
	}                                              \

DEFINE_CLEANUP_FUNC(yajl_val, yajl_tree_free)

#define pr_perror(fmt, ...) syslog(LOG_ERR, "oci-uid-hook <error>: " fmt ": %m\n", ##__VA_ARGS__)
#define pr_pinfo(fmt, ...) syslog(LOG_INFO, "oci-uid-hook <info>: " fmt "\n", ##__VA_ARGS__)
#define pr_pdebug(fmt, ...) syslog(LOG_DEBUG, "oci-uid-hook <debug>: " fmt "\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CONFIGSZ 65536

static int makepath(char *dir, mode_t mode) {
    if (!dir) {
	errno = EINVAL;
	return -1;
    }

    if (strlen(dir) == 1 && dir[0] == '/')
	return 0;

    makepath(dirname(strdupa(dir)), mode);

    return mkdir(dir, mode);
}

static int bind_mount(const char *src, const char *dest, int readonly) {
	if (mount(src, dest, "bind", MS_BIND, NULL) == -1) {
		pr_perror("Failed to mount %s on %s", src, dest);
		return -1;
	}
	//  Remount bind mount to read/only if requested by the caller
	if (readonly) {
		if (mount(src, dest, "bind", MS_REMOUNT|MS_BIND|MS_RDONLY, "") == -1) {
			pr_perror("Failed to remount %s readonly", dest);
			return -1;
		}
	}
	return 0;
}

/* error callback */
static int parser_errcb(struct libmnt_table *tb __attribute__ ((__unused__)),
			const char *filename, int line) {
	pr_perror("%s: parse error at line %d", filename, line);
	return 0;
}

static struct libmnt_table *parse_tabfile(const char *path) {
	int rc;
	struct libmnt_table *tb = mnt_new_table();

	if (!tb) {
		pr_perror("failed to initialize libmount table");
		return NULL;
	}

	mnt_table_set_parser_errcb(tb, parser_errcb);

	rc = mnt_table_parse_file(tb, path);

	if (rc) {
		mnt_free_table(tb);
		pr_perror("can't read %s", path);
		return NULL;
	}
	return tb;
}

/*
 * Get the contents of the file specified by its path
 */
static char *get_file_contents(const char *path) {
	_cleanup_close_ int fd = -1;
	if ((fd = open(path, O_RDONLY)) == -1) {
		pr_perror("Failed to open file for reading");
		return NULL;
	}

	char buffer[256];
	ssize_t rd;
	rd = read(fd, buffer, 256);
	if (rd == -1) {
		pr_perror("Failed to read file contents");
		return NULL;
	}

	buffer[rd] = '\0';

	return strdup(buffer);
}


static bool contains_mount(const char **config_mounts, unsigned len, const char *mount) {
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(mount, config_mounts[i])) {
			pr_pdebug("%s already present as a mount point in container configuration, skipping\n", mount);
			return true;
		}
	}
	return false;
}

/*
 * Move specified mount to temporary directory
 */
static int move_mount_to_tmp(const char *rootfs, const char *tmp_dir, const char *mount_dir, int offset) {
	int rc;
	_cleanup_free_ char *src = NULL;
	_cleanup_free_ char *dest = NULL;
	_cleanup_free_ char *post = NULL;

	rc = asprintf(&src, "%s/%s", rootfs, mount_dir);
	if (rc < 0) {
		pr_perror("Failed to allocate memory for src");
		return -1;
	}

	/* Find the second '/' to get the postfix */
	post = strdup(&mount_dir[offset]);

	if (!post) {
		pr_perror("Failed to allocate memory for postfix");
		return -1;
	}

	rc = asprintf(&dest, "%s/%s", tmp_dir, post);
	if (rc < 0) {
		pr_perror("Failed to allocate memory for dest");
		return -1;
	}

	if (makepath(dest, 0755) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir new dest: %s", dest);
			return -1;
		}
	}

	/* Move the mount to temporary directory */
	if ((mount(src, dest, "", MS_MOVE, "") == -1)) {
		pr_perror("Failed to move mount %s to %s", src, dest);
		return -1;
	}

	return 0;
}

static int move_mounts(const char *rootfs,
		       const char *path,
		       const char **config_mounts,
		       unsigned config_mounts_len,
		       char *options
	) {

	char mount_dir[PATH_MAX];
	snprintf(mount_dir, PATH_MAX, "%s%s", rootfs, path);

	/* Create a temporary directory to move the PATH mounts to */
	char temp_template[] = "/tmp/ocitmp.XXXXXX";

	char *tmp_dir = mkdtemp(temp_template);
	if (tmp_dir == NULL) {
		pr_perror("Failed to create temporary directory for mounts");
		return -1;
	}

	/* Create the PATH directory */
	if (!contains_mount(config_mounts, config_mounts_len, path)) {
		if (mkdir(mount_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir: %s", mount_dir);
				return -1;
			}
		}

		/* Mount tmpfs at new temp directory */
		if (mount("tmpfs", tmp_dir, "tmpfs", MS_NODEV|MS_NOSUID, options) == -1) {
			pr_perror("Failed to mount tmpfs at %s", tmp_dir);
			return -1;
		}

		/* Special case for /run/secrets which will not be in the
		   config_mounts */
		if (strcmp("/run", path) == 0) {
			if (move_mount_to_tmp(rootfs, tmp_dir, "/run/secrets", strlen(path)) < 0) {
				if (errno != EINVAL && errno != ENOENT) {
					pr_perror("Failed to move secrets dir");
					return -1;
				}
			}
		}

		/* Move other user specified mounts under PATH to temporary directory */
		for (unsigned i = 0; i < config_mounts_len; i++) {
			/* Match destinations that begin with PATH */
			if (!strncmp(path, config_mounts[i], strlen(path))) {
				if (move_mount_to_tmp(rootfs, tmp_dir, config_mounts[i], strlen(path)) < 0) {
					pr_perror("Failed to move %s to %s", config_mounts[i], tmp_dir);
					return -1;
				}
			}
		}

		/* Move temporary directory to PATH */
		if ((mount(tmp_dir, mount_dir, "", MS_MOVE, "") == -1)) {
			pr_perror("Failed to move mount %s to %s", tmp_dir, mount_dir);
			return -1;
		}
	}

	/* Remove the temp directory for PATH */
	if (rmdir(tmp_dir) < 0) {
		pr_perror("Failed to remove %s", tmp_dir);
		return -1;
	}
	return 0;
}

char *image_inspect(const char *image) {
	_cleanup_(yajl_tree_freep) yajl_val image_config = NULL;
	char *loutput;
	char *url = NULL;
	char *errbuf = NULL;
	char *image_cs = NULL;

	DOCKER *docker = docker_init(DOCKER_API_VERSION);
	asprintf(&url, "http://%s/images/%s/json", DOCKER_API_VERSION, image);
	if (docker) {
	CURLcode response = docker_get(docker, url);

	loutput = docker_buffer(docker);
	if (response != CURLE_OK) {
		return EXIT_FAILURE;
	}

	docker_destroy(docker);
	} else {
		fprintf(stderr, "ERROR: Failed to get get a docker client!\n");
	}

	image_config = yajl_tree_parse((const char *)loutput, errbuf, sizeof(errbuf));
	if (image_config == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	const char *config_image[] = { "Config", (const char *)0 };
	yajl_val v_iconfig = yajl_tree_get(image_config, config_image, yajl_t_object);
	const char *image_configs[] = { "User", (const char *)0 };
	yajl_val v_iuser = yajl_tree_get(v_iconfig, image_configs, yajl_t_string);
	asprintf(&image_cs, "%s", YAJL_GET_STRING(v_iuser));

	if (strcmp(image_cs, "") == 0) {
		image_cs = "0";
	}

	return image_cs;
}
 
int passwdfile_retrieval(const char *image, const char *cPath) {
	DOCKER *docker = docker_init(DOCKER_API_VERSION);
	_cleanup_(yajl_tree_freep) yajl_val cont_response = NULL;
	char *loutput;
	char errbuf[BUFLEN];
	char *url = NULL;
	char *post = NULL;
	const char *newPasswd = NULL;
	const char *newPasswdTar = NULL;
	const char *newCpath = NULL;
	char *c_id = NULL;

	asprintf(&url, "http://%s/containers/create", DOCKER_API_VERSION);
	asprintf(&post, "{\"Image\":\"%s\"}", image);

	if (docker) {
	CURLcode response = docker_post(docker, url,
									post);
	loutput = docker_buffer(docker);
	if (response != CURLE_OK) {
		pr_pdebug("%s", loutput);
	}

	cont_response = yajl_tree_parse((const char *)loutput, errbuf, sizeof(errbuf));
	if (cont_response == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	const char *cont_id[] = { "Id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(cont_response, cont_id, yajl_t_string);
	if (!v_id) {
		pr_perror("id not found in response");
		return EXIT_FAILURE;
	}
	char *cid = NULL;
	asprintf(&cid, "%s", YAJL_GET_STRING(v_id));

	asprintf(&newCpath, "%s/", cPath);
	asprintf(&newPasswd, "%s/passwd", cPath);
	asprintf(&newPasswdTar, "%s.tar", newPasswd);

	asprintf(&url, "http://%s/containers/%s/archive?path=%s", DOCKER_API_VERSION, cid, ETC_PASSWD);
	response = docker_get_archive(docker, url, newPasswdTar);
	loutput = docker_buffer(docker);
	if (response != CURLE_OK) {
		pr_pdebug("%s", loutput);
	}

	asprintf(&url, "http://%s/containers/%s?v=1&f=1", DOCKER_API_VERSION, cid);
	response = docker_delete(docker, url);
	loutput = docker_buffer(docker);
	if (response != CURLE_OK) {
		pr_pdebug("%s", loutput);
	}

	docker_destroy(docker);
	} else {
	fprintf(stderr, "ERROR: Failed to get get a docker client!\n");
	}

	char *untar_command = NULL;
	asprintf(&untar_command, "tar xf %s -C %s", newPasswdTar, newCpath);
	system(untar_command);

	if( access(newPasswd, F_OK) != -1 ) {
		remove(newPasswdTar);
	}

	return 0;
}

char *replace_str(char *str, char *orig, char *rep) {
  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig)))  // Is 'orig' even in 'str'?
    return str;

  strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'orig' st$
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

  return buffer;
}

int prestart(const char *rootfs,
		const char *id,
		int pid,
		const char *mount_label,
		const char **config_mounts,
		unsigned config_mounts_len,
		const char *cPath,
		const char *image,
		const char *cont_cu) {
	_cleanup_close_  int fd = -1;
	_cleanup_free_   char *options = NULL;

	char *image_u = image_inspect(image);

	// bypass hook if passed uid matches image user
	if (strcmp(image_u, cont_cu) == 0) {
		return EXIT_SUCCESS;
	}

	if (passwdfile_retrieval(image, cPath) != 0) {
        return EXIT_FAILURE;
	}

	char *newPasswd = NULL;
	char *newPasswdNew = NULL;
	char *image_username = NULL;
	char line_storage[100], buffer[100];
	int check, line_num = 1;
	asprintf(&newPasswd, "%s/passwd", cPath);
	
	// bypass hook, existing user name matches specified uid
	FILE *input = fopen(newPasswd, "r");
	char *c_user_search = NULL;
	asprintf(&c_user_search, ":x:%s:", cont_cu);
	while( fgets(line_storage, sizeof(line_storage), input) != NULL )  {
		check = 0;
		sscanf(line_storage,"%s",buffer);
		if(strstr(buffer,c_user_search) != NULL)  check = 1;
		if(check == 1) {
			remove(newPasswd);
			fclose(input);
			return EXIT_SUCCESS;
		}
		line_num++;
	}
	fclose(input);

	FILE *input2 = fopen(newPasswd, "r");
	char *i_user_search = NULL;
	asprintf(&i_user_search, ":x:%s:", image_u);
	while( fgets(line_storage, sizeof(line_storage), input2) != NULL )  {
		check = 0;
		sscanf(line_storage,"%s",buffer);
		if(strstr(buffer,i_user_search) != NULL)  check = 1;
		if(check == 1) {
			image_username = strtok(buffer,":");
		}
		line_num++;
	}
	fclose(input2);

	asprintf(&newPasswdNew, "%s.new", newPasswd);
	FILE *input3 = fopen(newPasswd, "r");
	FILE *inputnew = fopen(newPasswdNew, "w");
	char *i_user_s = NULL;
	char *i_user_r = NULL;
	asprintf(&i_user_s, "%s:x:%s:", image_username, image_u);
	asprintf(&i_user_r, "%s:x:%s:", image_username, cont_cu);
	while( fgets(line_storage, sizeof(line_storage), input3) != NULL )  {
		check = 0;
		sscanf(line_storage,"%[^\t\n]",buffer);
		if(strstr(buffer,i_user_s) != NULL)  check = 1;
		if(check != 1) {
			fputs(buffer, inputnew);
		} else {
			fputs(replace_str(buffer, i_user_s, i_user_r), inputnew);
		}
		fputs("\n", inputnew);
		line_num++;
	}
	fclose(input3);
	fclose(inputnew);

	remove(newPasswd);
	rename(newPasswdNew, newPasswd);
	chmod(newPasswd, 0400);
	pr_pinfo("%s", newPasswd);
	//mode

	int rc = -1;
	char process_mnt_ns_fd[PATH_MAX];
	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);

	fd = open(process_mnt_ns_fd, O_RDONLY);
	if (fd < 0) {
		pr_pinfo("Failed to open mnt namespace fd %s", process_mnt_ns_fd);
		return -1;
	}

	char *pch;
	char *self_v;
	char resolvedPath[PATH_MAX];
	realpath("/proc/self/ns/mnt", resolvedPath);
	pch = strtok(resolvedPath,":");
	while (pch != NULL)
	{
		pch = strtok(NULL, ":");
		if (pch != NULL) {
			self_v = pch;
		}
	}

	char *pchproc;
	char *proc_v;
	char resolvedPathProc[PATH_MAX];
	realpath(process_mnt_ns_fd, resolvedPathProc);
	pchproc = strtok(resolvedPathProc,":");
	while (pchproc != NULL)
	{
		pchproc = strtok(NULL, ":");
		if (pchproc != NULL) {
			proc_v = pchproc;
		}
	}

	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_pinfo("Failed to setns to %s", process_mnt_ns_fd);
		return -1;
	}
	close(fd);
	fd = -1;

	/* Switch to the root directory of ns */
	if (chdir("/") == -1) {
		pr_perror("Failed to chdir");
		return -1;
	}

	char *pchns;
	char *ns_v;
	char resolvedPathNs[PATH_MAX];
	realpath("/proc/self/ns/mnt", resolvedPathNs);
	pchns = strtok(resolvedPathNs,":");
	while (pchns != NULL)
	{
		pchns = strtok(NULL, ":");
		if (pchns != NULL) {
			ns_v = pchns;
		}
	}

	/*
	Ensure we've entered container mnt namespace before bind mount of /etc/passwd.
	*/
	if ((strcmp(self_v, proc_v) != 0) || (strcmp(proc_v, ns_v) == 0)) {
		pr_pdebug("mnt setns successful - %s", ns_v);
	} else {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	size_t rd;
	_cleanup_(yajl_tree_freep) yajl_val node = NULL;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	char errbuf[BUFLEN];
	char stateData[CONFIGSZ];
	char configData[CONFIGSZ];
	char *cPath;
	_cleanup_fclose_ FILE *fp = NULL;
	bool docker = false;

	stateData[0] = 0;
	errbuf[0] = 0;

	/* Read the entire config file from stdin */
	rd = fread((void *)stateData, 1, sizeof(stateData) - 1, stdin);
	if (rd == 0 && !feof(stdin)) {
		pr_perror("Error encountered on file read");
		return EXIT_FAILURE;
	} else if (rd >= sizeof(stateData) - 1) {
		pr_perror("Config file too big");
		return EXIT_FAILURE;
	}

	/* Parse the state */
	node = yajl_tree_parse((const char *)stateData, errbuf, sizeof(errbuf));
	if (node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	/* Extract values from the state json */
	const char *root_path[] = { "root", (const char *)0 };
	yajl_val v_root = yajl_tree_get(node, root_path, yajl_t_string);
	if (!v_root) {
		pr_perror("root not found in state");
		return EXIT_FAILURE;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		pr_perror("pid not found in state");
		return EXIT_FAILURE;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	if (!v_id) {
		pr_perror("id not found in state");
		return EXIT_FAILURE;
	}
	char *id = YAJL_GET_STRING(v_id);

	const char *ctr = getenv("container");
	if (ctr && !strncmp(ctr, DOCKER_CONTAINER, strlen(DOCKER_CONTAINER))) {
		docker = true;
	}

	if (docker) {
		if (argc < 3) {
			pr_perror("cannot find config file to use");
			return EXIT_FAILURE;
		}
		fp = fopen(argv[2], "r");
	} else {
		/* bundle_path must be specified for the OCI hooks, and from there we read the configuration file.
		   If it is not specified, then check that it is specified on the command line.  */
		return EXIT_FAILURE;
	}


	/* Parse the config file */
	if (fp == NULL) {
		pr_perror("Failed to open config file: %s", argv[2]);
		return EXIT_FAILURE;
	}
	rd = fread((void *)configData, 1, sizeof(configData) - 1, fp);
	if (rd == 0 && !feof(fp)) {
		pr_perror("error encountered on file read");
		return EXIT_FAILURE;
	} else if (rd >= sizeof(configData) - 1) {
		pr_perror("config file too big");
		return EXIT_FAILURE;
	}

	config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
	if (config_node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	char *cmd = NULL;
	char *image = NULL;
	char *mount_label = NULL;
	const char *cont_cu = NULL;
	const char **config_mounts = NULL;
	unsigned config_mounts_len = 0;

	if (!docker) {
		return EXIT_FAILURE;
	} else {
		/* Handle the Docker case here.  */
		/* Extract values from the config json */
		cPath = dirname(argv[2]);

		const char *mount_label_path[] = { "MountLabel", (const char *)0 };
		yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
		if (!v_mount) {
			pr_perror("MountLabel not found in config");
			return EXIT_FAILURE;
		}
		mount_label = YAJL_GET_STRING(v_mount);

		/* Extract values from the config json */
		const char *mount_points_path[] = { "MountPoints", (const char *)0 };
		yajl_val v_mps = yajl_tree_get(config_node, mount_points_path, yajl_t_object);
		if (!v_mps) {
			pr_perror("MountPoints not found in config");
			return EXIT_FAILURE;
		}

		config_mounts = YAJL_GET_OBJECT(v_mps)->keys;
		config_mounts_len = YAJL_GET_OBJECT(v_mps)->len;

		const char *cmd_path[] = { "Path", (const char *)0 };
		yajl_val v_cmd = yajl_tree_get(config_node, cmd_path, yajl_t_string);
		if (!v_cmd) {
			pr_perror("Path not found in config");
			return EXIT_FAILURE;
		}
		cmd = YAJL_GET_STRING(v_cmd);

		const char *image_path[] = { "Image", (const char *)0 };
		yajl_val v_image = yajl_tree_get(config_node, image_path, yajl_t_string);
		if (!v_image) {
			pr_perror("Image not found in config");
			return EXIT_FAILURE;
		}
		image = YAJL_GET_STRING(v_image);

		const char *config_cont[] = { "Config", (const char *)0 };
		yajl_val v_config = yajl_tree_get(config_node, config_cont, yajl_t_object);
		const char *cont_configs[] = { "User", (const char *)0 };
		yajl_val v_cuser = yajl_tree_get(v_config, cont_configs, yajl_t_string);
		asprintf(&cont_cu, "%s", YAJL_GET_STRING(v_cuser));
	}

	// bypass hook if /etc/passwd already bind mounted
	if (contains_mount(config_mounts, config_mounts_len, ETC_PASSWD)) {
		return EXIT_SUCCESS;
	}

	// bypass hook if passwd user is not numeric
    if (atoi(cont_cu)==0){
		return EXIT_SUCCESS;
	}

	/* OCI hooks set target_pid to 0 on poststop, as the container process alreadyok
	   exited.  If target_pid is bigger than 0 then it is the prestart hook.  */
	if ((argc > 2 && !strcmp("prestart", argv[1])) || target_pid) {
		if (prestart(rootfs, id, target_pid, mount_label, config_mounts, config_mounts_len, cPath, image, cont_cu) != 0) {
            return EXIT_FAILURE;
		}
	} else if ((argc > 2 && !strcmp("poststop", argv[1])) || (target_pid == 0)) {
        return EXIT_SUCCESS;
	} else {
		pr_perror("command not recognized: %s", argv[1]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}