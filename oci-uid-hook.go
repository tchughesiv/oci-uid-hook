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
	"time"

	"path"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"gopkg.in/yaml.v1"
)

// CONFIG uid hook configuration
const CONFIG = "/etc/oci-uid-hook.conf" // Config file for disabling hook
const apiVersion = "1.24"               // docker server api version

var state State
var containerJSON ContainerJSON
var settings struct {
	Disabled bool `yaml:"disabled"`
}

// FileInfo allows init check for container etc dir
type FileInfo struct {
	Name    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

// State holds information about the runtime state of the container.
type State struct {
	Version     string            `json:"version"`     // Version is the version of the specification that is supported.
	ID          string            `json:"id"`          // ID is the container ID
	Status      string            `json:"status"`      // Status is the runtime state of the container.
	Pid         int               `json:"pid"`         // Pid is the process ID for the container process.
	BundlePath  string            `json:"bundlePath"`  // BundlePath is the path to the container's bundle directory.
	Annotations map[string]string `json:"annotations"` // Annotations are the annotations associated with the container.
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

	// configFile := fmt.Sprintf("%s/config.json", state.BundlePath)
	configFile2 := os.Args[2]
	command := os.Args[1]
	cpath := path.Dir(configFile2)
	newPasswd := fmt.Sprintf("%s/passwd", cpath)

	// get additional container info
	jsonFile2, err := ioutil.ReadFile(configFile2)
	json.Unmarshal(jsonFile2, &containerJSON)
	ugidresult := strings.Split(containerJSON.Config.User, ":")
	user := ugidresult[0]

	switch command {
	case "prestart":
		{
			// proceed only if a new passwd file does not exist ... won't engage on pre-existing containers
			if _, err := os.Stat(newPasswd); os.IsNotExist(err) {
				log.Printf("UIDHook: %s %s", command, state.ID)
				if err = UIDHook(containerJSON.Config.Image, state.ID, user, newPasswd); err != nil {
					log.Fatalf("UIDHook failed: %v", err)
				}
			}
			return
		}
	case "poststop":
		{
			return
		}
	}
	log.Fatalf("Invalid command %q must be prestart|poststop", command)
}

// UIDHook for username recognition w/ arbitrary uid in the container
func UIDHook(image string, id string, user string, newPasswd string) error {
	os.Setenv("DOCKER_API_VERSION", apiVersion)
	//	ctx := context.Background()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil
	}

	// retrieve image user
	imageJSON, imageOUT, err := cli.ImageInspectWithRaw(ctx, image)
	if err != nil {
		return nil
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
	useruid := user

	// retrieve passwd file from container
	imageName := imageJSON.ID
	containerConfig := &container.Config{
		Image:      imageName,
		Entrypoint: []string{""},
		Cmd:        []string{""},
	}
	tcuid, err := cli.ContainerCreate(ctx, containerConfig, nil, nil, "")
	if err != nil {
		panic(err)
	}
	cfile, stat, err := cli.CopyFromContainer(ctx, tcuid.ID, "/etc/passwd")
	if err != nil {
		panic(err)
	}
	_ = stat
	crm := cli.ContainerRemove(ctx, tcuid.ID, types.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})
	if crm != nil {
		panic(err)
	}
	cpasswd, err := ioutil.ReadAll(cfile)

	var username string
	var usergid string
	var usercheck bool

	lines := strings.Split(string(cpasswd), "\n")
	for i, line := range lines {
		if strings.Contains(line, ":x:"+imageUser+":") {
			uidline := strings.Split(lines[i], ":")
			username = uidline[0]
			usergid = uidline[3]
		}
		if strings.Contains(line, ":x:"+useruid+":") {
			usercheck = true
		}
	}

	// create copy of passwd file in BundlePath
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(newPasswd, []byte(output), 0644)
	if err != nil {
		log.Fatalln(err)
	}

	// ensure specified uid doesn't already match image username
	if username != "" {
		if usercheck != true {
			log.Printf("UIDHook engaged: %s:x:%s:%s - %s", username, useruid, usergid, newPasswd)
			replace(username, imageUser, useruid, newPasswd)
		}
	}
	return nil
}

func replace(username string, imageUser string, useruid string, newPasswd string) {
	// find/replace w/ new uid

	// sed "s@${Username}:x:${User_image_uid}:@${Username}:x:${Useruid}:@g" /proc/${Pid}/root/etc/passwd > ${containers_dir}/${ID}/passwd

	// bind mount newPasswd into container @ /etc/passwd
	return
}
