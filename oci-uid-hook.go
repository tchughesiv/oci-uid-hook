// +build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"gopkg.in/yaml.v1"
)

// State holds information about the runtime state of the container.
type State struct {
	// Version is the version of the specification that is supported.
	Version string `json:"version"`
	// ID is the container ID
	ID string `json:"id"`
	// Status is the runtime state of the container.
	Status string `json:"status"`
	// Pid is the process ID for the container process.
	Pid int `json:"pid"`
	// BundlePath is the path to the container's bundle directory.
	BundlePath string `json:"bundlePath"`
	// Annotations are the annotations associated with the container.
	Annotations map[string]string `json:"annotations"`
}

// ContainerJSON is newly used struct along with MountPoint
type ContainerJSON struct {
	Mounts []MountPoint
	Config *container.Config
}

// MountPoint represents a mount point configuration inside the container. This is used for reporting the mountpoints in use by a container.
type MountPoint struct {
	Type        mount.Type `json:",omitempty"`
	Name        string     `json:",omitempty"`
	Source      string
	Destination string
	Driver      string `json:",omitempty"`
	Mode        string
	RW          bool
	Propagation mount.Propagation
}

// Config contains the configuration data about a container.
type Config struct {
	Hostname        string                // Hostname
	Domainname      string                // Domainname
	User            string                // User that will run the command(s) inside the container, also support user:group
	AttachStdin     bool                  // Attach the standard input, makes possible user interaction
	AttachStdout    bool                  // Attach the standard output
	AttachStderr    bool                  // Attach the standard error
	ExposedPorts    map[nat.Port]struct{} `json:",omitempty"` // List of exposed ports
	Tty             bool                  // Attach standard streams to a tty, including stdin if it is not closed.
	OpenStdin       bool                  // Open stdin
	StdinOnce       bool                  // If true, close stdin after the 1 attached client disconnects.
	Env             []string              // List of environment variable to set in the container
	Cmd             strslice.StrSlice     // Command to run when starting the container
	ArgsEscaped     bool                  `json:",omitempty"` // True if command is already escaped (Windows specific)
	Image           string                // Name of the image as it was passed by the operator (eg. could be symbolic)
	Volumes         map[string]struct{}   // List of volumes (mounts) used for the container
	WorkingDir      string                // Current directory (PWD) in the command will be launched
	Entrypoint      strslice.StrSlice     // Entrypoint to run when starting the container
	NetworkDisabled bool                  `json:",omitempty"` // Is network disabled
	MacAddress      string                `json:",omitempty"` // Mac Address of the container
	OnBuild         []string              // ONBUILD metadata that were defined on the image Dockerfile
	Labels          map[string]string     // List of labels set to this container
	StopSignal      string                `json:",omitempty"` // Signal to stop a container
	StopTimeout     *int                  `json:",omitempty"` // Timeout (in seconds) to stop a container
	Shell           strslice.StrSlice     `json:",omitempty"` // Shell for shell-form of RUN, CMD, ENTRYPOINT
}

// CONFIG file for disabling hook
const CONFIG = "/etc/oci-uid-hook.conf"

var state State
var containerJSON ContainerJSON
var settings struct {
	Disabled bool `yaml:"disabled"`
}

func main() {
	logwriter, err := syslog.New(syslog.LOG_NOTICE, "oci-uid-hook")
	if err == nil {
		log.SetOutput(logwriter)
	}

	// then config file settings
	data, err := ioutil.ReadFile(CONFIG)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("UIDHook Failed to read %s %v", CONFIG, err.Error())
		}
	} else {
		if err := yaml.Unmarshal(data, &settings); err != nil {
			log.Fatalf("UIDHook Failed to parse %s %v", CONFIG, err.Error())
		}
		if settings.Disabled {
			return
		}
	}

	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		log.Fatalf("UIDHook Failed %v", err.Error())
	}

	passwdFile := fmt.Sprintf("/proc/%d/root/etc/passwd", state.Pid)
	configFile := fmt.Sprintf("%s/config.json", state.BundlePath)
	configFile2 := os.Args[2]
	command := os.Args[1]

	// get additional container info
	jsonFile2, err := ioutil.ReadFile(configFile2)
	json.Unmarshal(jsonFile2, &containerJSON)
	ugidresult := strings.Split(containerJSON.Config.User, ":")
	user := ugidresult[0]
	// group := ugidresult[1]

	log.Printf("UIDHook: %s %s", command, state.ID)

	switch command {
	case "prestart":
		{
			if err = UIDHook(containerJSON.Config.Image, state.ID, int(state.Pid), configFile, configFile2, passwdFile, user); err != nil {
				log.Fatalf("UIDHook failed: %v", err)
			}
			return
		}
	case "poststart":
		{
			return
		}
	case "poststop":
		{
			return
		}
	}
	log.Fatalf("Invalid command %q must be prestart|poststart|poststop", command)
}

// UIDHook for arbitrary uid on the host system
func UIDHook(image string, id string, pid int, configFile string, configFile2 string, passwdFile string, user string) error {
	apiVersion := "1.24"
	os.Setenv("DOCKER_API_VERSION", apiVersion)
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	// retrieve image user
	imageJSON, imageOUT, err := cli.ImageInspectWithRaw(ctx, image)
	if err != nil {
		panic(err)
	}
	_ = imageOUT
	imageUser := imageJSON.Config.User

	// check if container user matches image user
	if eq := strings.Compare(imageUser, user); eq == 0 {
		return nil
	}

	// check if user is an integer
	if _, err := strconv.Atoi(user); err != nil {
		return nil
	}

	useruid, err := strconv.Atoi(user)

	// search passwd file
	f, err := ioutil.ReadFile(passwdFile)
	if err != nil {
		return err
	}

	// pwFile := string(f)
	// re := regexp.MustCompile(`\W+:x:` + imageUser + `:`)
	// res := re.Find(f)
	// convert shell logic to golang -
	//   Username=`grep \:x\:${User_image_uid}\: /proc/${Pid}/root/etc/passwd | awk -F ':' {'print $1'}`
	//   Usergid=`grep \:x\:${User_image_uid}\: /proc/${Pid}/root/etc/passwd | awk -F ':' {'print $4'}`
	//   User_check=`grep \:x\:${Useruid}\: /proc/${Pid}/root/etc/passwd | awk -F ':' {'print $1'}`
	//   if [ ! -z "${Username}" ] && [ -z "${User_check}" ]; then

	// create new passwd file in BundlePath
	lines := strings.Split(string(f), "\n")
	newPasswd := fmt.Sprintf("%s/passwd", state.BundlePath)

	// os.Link(passwdFile, newPasswd)
	for i, line := range lines {
		if strings.Contains(line, imageUser) {
			lines[i] = ""
		}
	}
	// find/replace
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(newPasswd, []byte(output), 0644)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("UIDHook engaged: %d %s %s", useruid, passwdFile, newPasswd)

	// bind mount newPasswd into container @ /etc/passwd
	return nil
}
