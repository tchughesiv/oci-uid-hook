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
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>
#include <libmount/libmount.h>

#include "config.h"

#define ETC_PASSWD "/etc/passwd"

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

static bool contains_mount(char **config_mounts, unsigned len, const char *mount) {
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(mount, config_mounts[i])) {
			pr_pinfo("%s already present as a mount in container, skipping...\n", mount);
			return true;
		}
	}
	return false;
}

char *image_inspect(char *image, const char *idriver) {
	size_t rd;
	_cleanup_(yajl_tree_freep) yajl_val image_node = NULL;
	char errbuf[BUFLEN];
	char imageData[CONFIGSZ];
	char *image_json = NULL;
	char *image_cs = NULL;
	_cleanup_fclose_ FILE *fp = NULL;

	char *pch;
	char *ihash = NULL;
	pch = strtok(image,":");
	while (pch != NULL)
	{
		pch = strtok(NULL, ":");
		if (pch != NULL) {
			ihash = pch;
		}
	}

	asprintf(&image_json, "/var/lib/docker/image/%s/imagedb/content/sha256/%s", idriver, ihash);
	fp = fopen(image_json, "r");
	/* Parse the config file */
	if (fp == NULL) {
		pr_perror("Failed to open config file: %s", image_json);
		return NULL;
	}
	rd = fread((void *)imageData, 1, sizeof(imageData) - 1, fp);
	if (rd == 0 && !feof(fp)) {
		pr_perror("error encountered on file read");
		return NULL;
	} else if (rd >= sizeof(imageData) - 1) {
		pr_perror("config file too big");
		return NULL;
	}

	image_node = yajl_tree_parse((const char *)imageData, errbuf, sizeof(errbuf));
	if (image_node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return NULL;
	}

	const char *config_image[] = { "config", (const char *)0 };
	yajl_val v_iconfig = yajl_tree_get(image_node, config_image, yajl_t_object);
	const char *image_configs[] = { "User", (const char *)0 };
	yajl_val v_iuser = yajl_tree_get(v_iconfig, image_configs, yajl_t_string);
	asprintf(&image_cs, "%s", YAJL_GET_STRING(v_iuser));

	if (strcmp(image_cs, "") == 0) {
		image_cs = "0";
	}

	return image_cs;
}

int prestart(const char *rootfs,
		const char *id,
		int pid,
		char *image,
		const char *cont_cu,
		const char *mlabel,
		const char *idriver,
		const char *bp) {
	_cleanup_close_  int fd = -1;
	_cleanup_free_   char *options = NULL;

	char *image_u = image_inspect(image, idriver);
	if (image_u == NULL) {
		return EXIT_FAILURE;
	}
	
	// bypass hook if passed uid matches image user
	if (strcmp(image_u, cont_cu) == 0) {
		return EXIT_SUCCESS;
	}

	char process_mnt_ns_fd[PATH_MAX];
	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);

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

	fd = open(process_mnt_ns_fd, O_RDONLY);
	if (fd < 0) {
		pr_pinfo("Failed to open mnt namespace fd %s", process_mnt_ns_fd);
		return -1;
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

	char dest[PATH_MAX];
	snprintf(dest, PATH_MAX, "%s%s", rootfs, ETC_PASSWD);
	
	char *newPasswd = dest;
	char *newPasswdNew = NULL;
	char *image_username = NULL;
	char line_storage[100], buffer[100];
	int check, line_num = 1;
	asprintf(&newPasswdNew, "%s/passwd", bp);
	
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
			char *image_un = strtok(buffer,":");
			asprintf(&image_username, "%s", image_un);
		}
		line_num++;
	}
	fclose(input2);

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

	if (strcmp(mlabel, "") != 0) {
		if (setfilecon (newPasswdNew, mlabel) < 0) {
			pr_perror("Failed to set context %s on %s", newPasswdNew, mlabel);
		}
	}
	chmod(newPasswdNew, 0644);
	pr_pinfo("%s", newPasswdNew);

	/*
	Ensure we've entered container mnt namespace before bind mount of /etc/passwd.
	*/
	if ((strcmp(self_v, proc_v) != 0) && (strcmp(proc_v, ns_v) == 0)) {

		// bind mount /etc/passwd
		if (bind_mount(newPasswdNew, dest, false) < 0) {
			return -1;
		}
	} else {
		// how better error out w/o throwing oci errors? 
		return EXIT_FAILURE;
	}

	pr_pinfo("docker exec %s whoami", id);
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
	size_t rd;
	_cleanup_(yajl_tree_freep) yajl_val node = NULL;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	_cleanup_fclose_ FILE *fp = NULL;
	char errbuf[BUFLEN];
	char stateData[CONFIGSZ];
	char configData[CONFIGSZ];
	char *cont_cu = NULL;
	char **config_mounts = NULL;
	char *idriver = NULL;
	char *image = NULL;
	char *mlabel = NULL;
	unsigned config_mounts_len = 0;

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

	const char *bundle_path[] = { "bundlePath", (const char *)0 };
	yajl_val v_bundle_path = yajl_tree_get(node, bundle_path, yajl_t_string);
	if (!v_bundle_path) {
		pr_perror("bundlePath not found in state");
		return EXIT_FAILURE;
	}
	char *bp = YAJL_GET_STRING(v_bundle_path);
	char config_file_name[PATH_MAX];
	sprintf(config_file_name, "%s/config.json", bp);


	/* OCI hooks set target_pid to 0 on poststop, as the container process alreadyok
	   exited.  If target_pid is bigger than 0 then it is the prestart hook.  */
	if ((argc > 2 && !strcmp("prestart", argv[1])) || target_pid) {

		// fp = fopen(config_file_name, "r");
		fp = fopen(argv[2], "r");

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

		/* Extract values from the config json */
		const char *mount_points_path[] = { "MountPoints", (const char *)0 };
		yajl_val v_mps = yajl_tree_get(config_node, mount_points_path, yajl_t_object);
		if (!v_mps) {
			pr_perror("MountPoints not found in config");
			return EXIT_FAILURE;
		}

		config_mounts = YAJL_GET_OBJECT(v_mps)->keys;
		config_mounts_len = YAJL_GET_OBJECT(v_mps)->len;

		const char *driver_type[] = { "Driver", (const char *)0 };
		yajl_val v_driver = yajl_tree_get(config_node, driver_type, yajl_t_string);
		if (!v_driver) {
			pr_perror("Image not found in config");
			return EXIT_FAILURE;
		}
		idriver = YAJL_GET_STRING(v_driver);

		const char *image_path[] = { "Image", (const char *)0 };
		yajl_val v_image = yajl_tree_get(config_node, image_path, yajl_t_string);
		if (!v_image) {
			pr_perror("Image not found in config");
			return EXIT_FAILURE;
		}
		image = YAJL_GET_STRING(v_image);

		const char *mount_label[] = { "MountLabel", (const char *)0 };
		yajl_val v_label = yajl_tree_get(config_node, mount_label, yajl_t_string);
		if (!v_label) {
			pr_perror("Image not found in config");
			return EXIT_FAILURE;
		}
		mlabel = YAJL_GET_STRING(v_label);

		// process.user.uid
		const char *config_cont[] = { "Config", (const char *)0 };
		yajl_val v_config = yajl_tree_get(config_node, config_cont, yajl_t_object);
		const char *cont_configs[] = { "User", (const char *)0 };
		yajl_val v_cuser = yajl_tree_get(v_config, cont_configs, yajl_t_string);
		asprintf(&cont_cu, "%s", YAJL_GET_STRING(v_cuser));


		// bypass hook if /etc/passwd already bind mounted
		if (contains_mount(config_mounts, config_mounts_len, ETC_PASSWD)) {
			return EXIT_SUCCESS;
		}
		// bypass hook if passed in user is not numeric
		if (atoi(cont_cu)==0){
			return EXIT_SUCCESS;
		}

		if (prestart(rootfs, id, target_pid, image, cont_cu, mlabel, idriver, bp) != 0) {
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