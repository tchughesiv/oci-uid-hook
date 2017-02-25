#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <linux/limits.h>
#include <yajl/yajl_tree.h>
#include <libmount/libmount.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

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

	if ((strcmp(image_cs, "") == 0) || image_cs == NULL) {
		image_cs = "0";
	}

	return image_cs;
}

struct passwd *fgetpwnam(FILE *pw_file,char *name) {
	struct passwd *ret;
	while ((ret=fgetpwent(pw_file))!=NULL) {
		if(strcmp(ret->pw_name,name)==0) break;
	}
	return(ret);
}

struct passwd *fgetpwuid(FILE *pw_file,uid_t uid) {
	struct passwd *ret;
	while ((ret=fgetpwent(pw_file))!=NULL) {
		if (ret->pw_uid == uid) break;
	}
	return(ret);
}

int prestart(const char *rootfs,
		const char *id,
		int pid,
		char *image,
		const char *cont_cu,
		const char *mlabel,
		const char *idriver,
		char *cPath) {
	_cleanup_close_  int fd = -1;
	_cleanup_free_   char *options = NULL;
	char nrootfs[PATH_MAX];
	realpath(rootfs, nrootfs);
	char dest[PATH_MAX];
	snprintf(dest, PATH_MAX, "%s%s", nrootfs, ETC_PASSWD);
	char *newPasswd = dest;
	char *newPasswdNew = NULL;
	char *image_username = NULL;
	char *line_un = NULL;
	char *image_id = NULL;
	char *group_id = NULL;
	char process_mnt_ns_fd[PATH_MAX];
	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);
	FILE *pwd_fd = NULL;

	if ((strcmp(cont_cu, "") == 0) || cont_cu == NULL) {
		cont_cu = "0";
	}

	// bypass hook if user exists with specified uid
	pwd_fd = fopen(newPasswd, "r");
	if (isdigit(cont_cu[0])) {
		uid_t uid = atoi(cont_cu);
		struct passwd *pwdt = fgetpwuid(pwd_fd, uid);
		if (pwdt != 0) {
			return EXIT_SUCCESS;
		}
	}
	fclose(pwd_fd);

	// retrieve image user
	char *image_u = image_inspect(image, idriver);

	// get user details from container passwd file
	pwd_fd = fopen(newPasswd, "r");
	if (isdigit(image_u[0])) {
		uid_t uid = atoi(image_u);
		struct passwd *pwd = fgetpwuid(pwd_fd, uid);
		// bypass if image user doesn't exist in passwd db
		if (pwd == 0) {
			return EXIT_SUCCESS;
		} else {
		asprintf(&image_username, "%s", pwd->pw_name);
		asprintf(&image_id, "%d", pwd->pw_uid);
		asprintf(&group_id, "%d", pwd->pw_gid);
		}
	} else {
		struct passwd *pwd = fgetpwnam(pwd_fd, image_u);
		// bypass if image user doesn't exist in passwd db
		if (pwd == 0) {
			return EXIT_SUCCESS;
		} else {
		asprintf(&image_username, "%s", pwd->pw_name);
		asprintf(&image_id, "%d", pwd->pw_uid);
		asprintf(&group_id, "%d", pwd->pw_gid);
		}
	}
	fclose(pwd_fd);

	char *pch;
	char *self_v;
	char resolvedPath[PATH_MAX];
	realpath("/proc/self/ns/mnt", resolvedPath);
	pch = strtok(resolvedPath,":");
	while (pch != NULL) {
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
	while (pchproc != NULL) {
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
	while (pchns != NULL) {
		pchns = strtok(NULL, ":");
		if (pchns != NULL) {
			ns_v = pchns;
		}
	}

	// create new passwd file
	asprintf(&newPasswdNew, "%s/passwd", cPath);
	if (image_username != NULL) {
		FILE *input = fopen(newPasswd, "r");
		FILE *inputnew = fopen(newPasswdNew, "w");
		struct passwd *ptr;
		uid_t cuid = atoi(cont_cu);
		while ((ptr=fgetpwent(input))!=NULL) {
			asprintf(&line_un, "%s", ptr->pw_name);
			if (strcmp(line_un, image_username) == 0) {
				ptr->pw_uid = cuid;
			}
			putpwent(ptr, inputnew);
		}
		fclose(input);
		fclose(inputnew);

		#ifdef HAVE_SELINUX
		if (strcmp(mlabel, "") != 0) {
			if (setfilecon (newPasswdNew, mlabel) < 0) {
				pr_perror("Failed to set context %s on %s", newPasswdNew, mlabel);
			}
		}
		#endif

		chmod(newPasswdNew, 0644);
		pr_pdebug("%s", newPasswdNew);

		/*
		Ensure we've entered container mnt namespace before bind mount of /etc/passwd.
		*/
		if ((strcmp(self_v, proc_v) != 0) && (strcmp(proc_v, ns_v) == 0)) {
			// bind mount /etc/passwd
			if (bind_mount(newPasswdNew, newPasswd, false) < 0) {
				return -1;
			}
		} else {
			// how better error out w/o throwing oci errors? 
			return EXIT_SUCCESS;
		}

		pr_pdebug("docker exec %s id", id);
	}
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
	char cPath[PATH_MAX];
	unsigned config_mounts_len = 0;

	stateData[0] = 0;
	errbuf[0] = 0;

	/* Read the entire config file from stdin */
	rd = fread((void *)stateData, 1, sizeof(stateData) - 1, stdin);
	if (rd == 0 && !feof(stdin)) {
		pr_perror("Error encountered on file read");
		return EXIT_SUCCESS;
	} else if (rd >= sizeof(stateData) - 1) {
		pr_perror("Config file too big");
		return EXIT_SUCCESS;
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
		return EXIT_SUCCESS;
	}

	/* Extract values from the state json */
	const char *root_path[] = { "root", (const char *)0 };
	yajl_val v_root = yajl_tree_get(node, root_path, yajl_t_string);
	if (!v_root) {
		pr_perror("root not found in state");
		return EXIT_SUCCESS;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		pr_perror("pid not found in state");
		return EXIT_SUCCESS;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	if (!v_id) {
		pr_perror("id not found in state");
		return EXIT_SUCCESS;
	}
	char *id = YAJL_GET_STRING(v_id);
	
	/*
	const char *bundle_path[] = { "bundlePath", (const char *)0 };
	yajl_val v_bundle_path = yajl_tree_get(node, bundle_path, yajl_t_string);
	if (!v_bundle_path) {
		pr_perror("bundlePath not found in state");
		return EXIT_SUCCESS;
	}
	char *bp = YAJL_GET_STRING(v_bundle_path);
	char config_file_name[PATH_MAX];
	sprintf(config_file_name, "%s/config.json", bp);
	*/

	/* OCI hooks set target_pid to 0 on poststop, as the container process alreadyok
	   exited.  If target_pid is bigger than 0 then it is the prestart hook.  */
	if ((argc > 2 && !strcmp("prestart", argv[1])) || target_pid) {
		// fp = fopen(config_file_name, "r");
		fp = fopen(argv[2], "r");

		/* Parse the config file */
		if (fp == NULL) {
			pr_perror("Failed to open config file: %s", argv[2]);
			return EXIT_SUCCESS;
		}
		rd = fread((void *)configData, 1, sizeof(configData) - 1, fp);
		if (rd == 0 && !feof(fp)) {
			pr_perror("error encountered on file read");
			return EXIT_SUCCESS;
		} else if (rd >= sizeof(configData) - 1) {
			pr_perror("config file too big");
			return EXIT_SUCCESS;
		}

		config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
		if (config_node == NULL) {
			pr_perror("parse_error: ");
			if (strlen(errbuf)) {
				pr_perror(" %s", errbuf);
			} else {
				pr_perror("unknown error");
			}
			return EXIT_SUCCESS;
		}

		/* Extract values from the config json */
		const char *config_cont[] = { "Config", (const char *)0 };
		yajl_val v_config = yajl_tree_get(config_node, config_cont, yajl_t_object);
		const char *cont_configs[] = { "User", (const char *)0 };
		yajl_val v_cuser = yajl_tree_get(v_config, cont_configs, yajl_t_string);
		asprintf(&cont_cu, "%s", YAJL_GET_STRING(v_cuser));

		// bypass hook if passed in user is not numeric
		if (isalpha(cont_cu[0])) {
			return EXIT_SUCCESS;
		}

		const char *mount_points_path[] = { "MountPoints", (const char *)0 };
		yajl_val v_mps = yajl_tree_get(config_node, mount_points_path, yajl_t_object);
		if (!v_mps) {
			pr_perror("MountPoints not found in config");
			return EXIT_SUCCESS;
		}

		config_mounts = YAJL_GET_OBJECT(v_mps)->keys;
		config_mounts_len = YAJL_GET_OBJECT(v_mps)->len;

		const char *driver_type[] = { "Driver", (const char *)0 };
		yajl_val v_driver = yajl_tree_get(config_node, driver_type, yajl_t_string);
		if (!v_driver) {
			pr_perror("driver not found in config");
			return EXIT_SUCCESS;
		}
		idriver = YAJL_GET_STRING(v_driver);

		const char *image_path[] = { "Image", (const char *)0 };
		yajl_val v_image = yajl_tree_get(config_node, image_path, yajl_t_string);
		if (!v_image) {
			pr_perror("Image not found in config");
			return EXIT_SUCCESS;
		}
		image = YAJL_GET_STRING(v_image);

		#ifdef HAVE_SELINUX
		const char *mount_label[] = { "MountLabel", (const char *)0 };
		yajl_val v_label = yajl_tree_get(config_node, mount_label, yajl_t_string);
		if (!v_label) {
			pr_perror("mountlabel not found in config");
			return EXIT_SUCCESS;
		}
		mlabel = YAJL_GET_STRING(v_label);
		#endif

		// bypass hook if /etc/passwd already bind mounted
		if (contains_mount(config_mounts, config_mounts_len, ETC_PASSWD)) {
			return EXIT_SUCCESS;
		}

		realpath(dirname(argv[2]), cPath);
		if (prestart(rootfs, id, target_pid, image, cont_cu, mlabel, idriver, cPath) != 0) {
            return EXIT_SUCCESS;
		}
	} else if ((argc > 2 && !strcmp("poststop", argv[1])) || (target_pid == 0)) {
        return EXIT_SUCCESS;
	} else {
		pr_perror("command not recognized: %s", argv[1]);
		return EXIT_SUCCESS;
	}
	return EXIT_SUCCESS;
}