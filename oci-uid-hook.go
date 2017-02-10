// +build linux

package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/daemon/network"
	"github.com/docker/go-connections/nat"
	"gopkg.in/yaml.v1"
)

// CONFIG uid hook configuration
const CONFIG = "/etc/oci-uid-hook.conf" // Config file for disabling hook
const apiVersion = "1.24"               // docker server api version
var state State
var containerJSON ContainerJSON

func main() {
	os.Setenv("DOCKER_API_VERSION", apiVersion)
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
	procPasswd := fmt.Sprintf("/proc/%d/root/etc/passwd", state.Pid)
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
				if err = UIDHook(containerJSON.Config.Image, state.ID, user, procPasswd, cpath, newPasswd); err != nil {
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
func UIDHook(image string, id string, user string, procPasswd string, cpath string, newPasswd string) error {
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
	file := "/etc/passwd"
	imageName := imageJSON.ID
	containerConfig := &container.Config{
		Image:      imageName,
		Entrypoint: []string{""},
		Cmd:        []string{""},
	}
	tcuid, err := cli.ContainerCreate(ctx, containerConfig, nil, nil, "")
	if err != nil {
		log.Fatalln(err)
	}
	cfile, stat, err := cli.CopyFromContainer(ctx, tcuid.ID, file)
	if err != nil {
		log.Fatalln(err)
	}
	_ = stat
	c, err := ioutil.ReadAll(cfile)
	if err != nil {
		log.Fatalln(err)
	}
	cfile.Close()
	crm := cli.ContainerRemove(ctx, tcuid.ID, types.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})
	if crm != nil {
		log.Fatalln(err)
	}

	// create copy of passwd file in cpath
	err = ioutil.WriteFile(newPasswd+".tar", c, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	err = untar(newPasswd+".tar", cpath)
	if err != nil {
		log.Fatalln(err)
	}
	err = os.Remove(newPasswd + ".tar")
	if err != nil {
		log.Fatalln(err)
	}

	var username string
	var usercheck bool
	// var usergid string

	pwFile, err := os.Open(newPasswd)
	in, err := ioutil.ReadAll(pwFile)
	lines := strings.Split(string(in), "\n")
	for i, line := range lines {
		if strings.Contains(line, ":x:"+imageUser+":") {
			uidline := strings.Split(lines[i], ":")
			username = uidline[0]
			// usergid = uidline[3]
		}
		if strings.Contains(line, ":x:"+useruid+":") {
			usercheck = true
		}
	}
	findS := fmt.Sprintf("%s:x:%s:", username, imageUser)
	replaceS := fmt.Sprintf("%s:x:%s:", username, useruid)

	// ensure specified uid doesn't already match image username
	if username != "" {
		if usercheck != true {
			log.Printf("UIDHook engaged: %s %s", newPasswd, procPasswd)
			replace(findS, replaceS, lines, newPasswd)
			mount(id, username, imageUser, useruid, newPasswd)
		}
	}
	return nil
}

func replace(findS string, replaceS string, lines []string, newPasswd string) {
	// find/replace w/ new uid
	var check string
	for i, line := range lines {
		if strings.Contains(line, findS) {
			lines[i] = strings.Replace(lines[i], findS, replaceS, -1)
			check = lines[i]
		}
	}
	output := strings.Join(lines, "\n")
	err := ioutil.WriteFile(newPasswd, []byte(output), 0644)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("UIDHook replaced w/: %s", check)
	return
}

func mount(id string, username string, imageUser string, useruid string, newPasswd string) {
	// !!!!!!!!!!!!!!!!!!!!!!!!!!
	// modify the jsonFile2 directly??... add a /etc/passwd mount point
	//	containerJSON.mountpoints{
	//		"/etc/passwd": {
	//			"Source":      newPasswd,
	//			"Destination": "/etc/passwd",
	//			"RW":          true,
	//			"Name":        "",
	//			"Driver":      "",
	//			"Relabel":     "Z",
	//			"Propagation": "rprivate",
	//			"Named":       false,
	//			"ID":          "",
	//		},
	//	}

	// bind mount newPasswd into container @ /etc/passwd
	//	updatestatus, err := cli.ContainerUpdate(ctx, id, container.UpdateConfig{
	//		Resources: container.Resources{
	//			Devices: []string{""},
	//		},
	//	})
	//	if err != nil {
	//		log.Fatal(err)
	//	}

	log.Printf("UIDHook mount:")
}

func untar(tarball, target string) error {
	reader, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(file, tarReader)
		if err != nil {
			return err
		}
	}
	return nil
}

var settings struct {
	Disabled bool `yaml:"disabled"`
}

// Propagation constants
const (
	// PropagationRPrivate RPRIVATE
	PropagationRPrivate Propagation = "rprivate"
	// PropagationPrivate PRIVATE
	PropagationPrivate Propagation = "private"
	// PropagationRShared RSHARED
	PropagationRShared Propagation = "rshared"
	// PropagationShared SHARED
	PropagationShared Propagation = "shared"
	// PropagationRSlave RSLAVE
	PropagationRSlave Propagation = "rslave"
	// PropagationSlave SLAVE
	PropagationSlave Propagation = "slave"
)

// Type constants
const (
	// TypeBind is the type for mounting host dir
	TypeBind Type = "bind"
	// TypeVolume is the type for remote storage volumes
	TypeVolume Type = "volume"
	// TypeTmpfs is the type for mounting tmpfs
	TypeTmpfs Type = "tmpfs"
)

// Propagations is the list of all valid mount propagations
var Propagations = []Propagation{
	PropagationRPrivate,
	PropagationPrivate,
	PropagationRShared,
	PropagationShared,
	PropagationRSlave,
	PropagationSlave,
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

// ContainerJSONBase contains response of Engine API:
// GET "/containers/{name:.*}/json"
type ContainerJSONBase struct {
	ID              string `json:"Id"`
	Created         string
	Path            string
	Args            []string
	Image           string
	ResolvConfPath  string
	HostnamePath    string
	HostsPath       string
	LogPath         string
	Name            string
	RestartCount    int
	Driver          string
	MountLabel      string
	ProcessLabel    string
	AppArmorProfile string
	ExecIDs         []string
	HostConfig      *container.HostConfig
	SizeRw          *int64 `json:",omitempty"`
	SizeRootFs      *int64 `json:",omitempty"`
}

// ContainerJSON is newly used struct along with MountPoint
type ContainerJSON struct {
	*ContainerJSONBase
	Mounts          []MountPoint
	Config          *container.Config
	NetworkSettings *NetworkSettings
}

// NetworkSettings exposes the network settings in the api
type NetworkSettings struct {
	Networks map[string]*network.EndpointSettings
}

// MountPoint represents a mount point configuration inside the container.
// This is used for reporting the mountpoints in use by a container.
type MountPoint struct {
	Name        string `json:",omitempty"`
	Source      string
	Destination string
	Driver      string `json:",omitempty"`
	Mode        string
	RW          bool
	Propagation string
	Named       bool
	Relabel     string
}

// Type represents the type of a mount.
type Type string

// Mount represents a mount (volume).
type Mount struct {
	Type Type `json:",omitempty"`
	// Source specifies the name of the mount. Depending on mount type, this
	// may be a volume name or a host path, or even ignored.
	// Source is not supported for tmpfs (must be an empty value)
	Source   string `json:",omitempty"`
	Target   string `json:",omitempty"`
	ReadOnly bool   `json:",omitempty"`

	BindOptions   *BindOptions   `json:",omitempty"`
	VolumeOptions *VolumeOptions `json:",omitempty"`
	TmpfsOptions  *TmpfsOptions  `json:",omitempty"`
}

// Propagation represents the propagation of a mount.
type Propagation string

// BindOptions defines options specific to mounts of type "bind".
type BindOptions struct {
	Propagation Propagation `json:",omitempty"`
}

// VolumeOptions represents the options for a mount of type volume.
type VolumeOptions struct {
	NoCopy       bool              `json:",omitempty"`
	Labels       map[string]string `json:",omitempty"`
	DriverConfig *Driver           `json:",omitempty"`
}

// Driver represents a volume driver.
type Driver struct {
	Name    string            `json:",omitempty"`
	Options map[string]string `json:",omitempty"`
}

// TmpfsOptions defines options specific to mounts of type "tmpfs".
type TmpfsOptions struct {
	// Size sets the size of the tmpfs, in bytes.
	//
	// This will be converted to an operating system specific value
	// depending on the host. For example, on linux, it will be converted to
	// use a 'k', 'm' or 'g' syntax. BSD, though not widely supported with
	// docker, uses a straight byte value.
	//
	// Percentages are not supported.
	SizeBytes int64 `json:",omitempty"`
	// Mode of the tmpfs upon creation
	Mode os.FileMode `json:",omitempty"`

	// TODO(stevvooe): There are several more tmpfs flags, specified in the
	// daemon, that are accepted. Only the most basic are added for now.
	//
	// From docker/docker/pkg/mount/flags.go:
	//
	// var validFlags = map[string]bool{
	// 	"":          true,
	// 	"size":      true, X
	// 	"mode":      true, X
	// 	"uid":       true,
	// 	"gid":       true,
	// 	"nr_inodes": true,
	// 	"nr_blocks": true,
	// 	"mpol":      true,
	// }
	//
	// Some of these may be straightforward to add, but others, such as
	// uid/gid have implications in a clustered system.
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
