#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <pwd.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <security/pam_appl.h>

int pam_tty_conv(int num_msg, struct pam_message **msg,
                 struct pam_response **response, void *appdata_ptr) {
  return 0;
}

#define MODULE "../target/release/libpam_tailscale.so"
//#define MODULE "./pam_ignore.so"

int main() {
  struct pam_conv conv = { pam_tty_conv, NULL };
	pam_handle_t *pamh;
	struct passwd *pw;
  int err;

	if ((pw = getpwuid(getuid())) == NULL) {
		(void) fprintf(stderr, "plock: Can't get username: %s\n",
                   strerror(errno));
		exit(1);
	}

  err = pam_start("pam_test", pw->pw_name, &conv, &pamh);
	if (err != PAM_SUCCESS) {
		(void) fprintf(stderr, "plock: pam_start failed: %s\n",
                   pam_strerror(pamh, err));
		exit(1);
	}

  char *rhost = "100.127.23.80";
  err = pam_set_item(pamh, PAM_RHOST, &rhost);
	if (err != PAM_SUCCESS) {
		(void) fprintf(stderr, "plock: pam_set_item failed: %s\n",
                   pam_strerror(pamh, err));
		exit(1);
	}

  void *handle;
  handle = dlopen(MODULE, RTLD_LAZY);
  if (handle == NULL) {
    perror("can't open pam module");
    return 1;
  }

  int (*auth)(pam_handle_t *, int, int, const char **) = dlsym(handle, "pam_sm_authenticate");
  if (!auth(pamh, 0, 0, NULL)) {
    printf("auth failed\n");
    return 2;
  }
  printf("auth worked!\n");

  return 0;
}
