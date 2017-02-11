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
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gopkg.in/yaml.v1"
)

const (
	config           = "/etc/oci-uid-hook.conf" // Config file for disabling hook
	dockerAPIversion = "1.24"                   // docker server api version
	pfile            = "/etc/passwd"            // passwd path in container
	ctxTimeout       = 10 * time.Second         // docker client timeout
)

var (
	spec          specs.Spec
	state         specs.State
	containerJSON ContainerJSON
	check         string
	username      string
	usercheck     bool
	//usergid string

	settings struct {
		Disabled bool `yaml:"disabled"`
	}
)

// ContainerJSON is newly used struct along with MountPoint
type ContainerJSON struct {
	*types.ContainerJSONBase
	MountPoints MountPointData
	Config      *container.Config
}

// MountPointData represents a mount point configuration inside the container.
type MountPointData struct {
	MountPoint types.MountPoint `json:"/etc/passwd"`
}

func main() {
	os.Setenv("DOCKER_API_VERSION", dockerAPIversion)

	logwriter, err := syslog.New(syslog.LOG_NOTICE, "oci-uid-hook")
	if err == nil {
		log.SetOutput(logwriter)
	}

	// config file settings
	data, err := ioutil.ReadFile(config)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("UIDHook Failed to read %s %v", config, err.Error())
		}
	} else {
		if err := yaml.Unmarshal(data, &settings); err != nil {
			log.Printf("UIDHook Failed to parse %s %v", config, err.Error())
		}
		if settings.Disabled {
			return
		}
	}

	command := os.Args[1]
	configFile := os.Args[2]
	cpath := path.Dir(configFile)

	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}
	// newconfigFile := fmt.Sprintf("%s/config.json", state.BundlePath)

	// get additional container info
	jsonFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Println(err)
	}
	json.Unmarshal(jsonFile, &containerJSON)

	switch command {
	case "prestart":
		{
			if err = UIDHook(command, containerJSON.Config.Image, state.ID, cpath); err != nil {
			}
			return
		}
	case "poststop":
		{
			return
		}
	}
	log.Printf("Invalid command %q must be prestart|poststop", command)
}

// UIDHook for username recognition w/ arbitrary uid in the container
func UIDHook(command string, image string, id string, cpath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	cli, _ := client.NewEnvClient()

	// retrieve image user
	imageJSON, imageOUT, err := cli.ImageInspectWithRaw(ctx, image)
	if err != nil {
		log.Println(err)
	}
	_ = imageOUT
	imageUser := imageJSON.Config.User
	ugidresult := strings.Split(containerJSON.Config.User, ":")
	user := ugidresult[0]

	// check if container user matches image user
	if eq := strings.Compare(imageUser, user); eq == 0 {
		return nil
	}

	// check if user is an integer
	if _, err := strconv.Atoi(user); err != nil {
		return nil
	}

	log.Printf("%s %s", command, state.ID)

	// check for existing /etc/passwd bind mount... bypass if exists
	pwMount := containerJSON.MountPoints.MountPoint.Destination
	if pwMount != "" {
		log.Printf("hook bypassed: %s already mounted", pfile)
		return nil
	}

	// retrieve passwd file from container
	newPasswd := fmt.Sprintf("%s/passwd", cpath)
	// procPasswd := fmt.Sprintf("/proc/%d/root/etc/passwd", state.Pid)
	imageName := imageJSON.ID
	fileRetrieve(imageName, newPasswd, cpath)
	if err != nil {
		log.Println(err)
	}

	pwFile, err := os.Open(newPasswd)
	useruid := user
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

	// ensure specified uid doesn't already match an image username
	if username != "" {
		if usercheck != true {
			uidReplace(findS, replaceS, lines, newPasswd)
			mountPasswd(id, username, imageUser, useruid, newPasswd)
		}
	}
	return err
}

// fileRetrieve creates a temp container and copies a file from it
func fileRetrieve(imageName string, newPasswd string, cpath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	cli, _ := client.NewEnvClient()

	containertmpConfig := &container.Config{
		Image:      imageName,
		Entrypoint: []string{""},
		Cmd:        []string{""},
	}
	tcuid, err := cli.ContainerCreate(ctx, containertmpConfig, nil, nil, "")
	if err != nil {
		log.Println(err)
	}
	cfile, stat, err := cli.CopyFromContainer(ctx, tcuid.ID, pfile)
	if err != nil {
		log.Println(err)
	}
	_ = stat
	c, err := ioutil.ReadAll(cfile)
	if err != nil {
		log.Println(err)
	}
	cfile.Close()
	crm := cli.ContainerRemove(ctx, tcuid.ID, types.ContainerRemoveOptions{
		//	RemoveVolumes: true,
		Force: true,
	})
	if crm != nil {
		log.Println(err)
	}

	// create copy of passwd file in cpath
	err = ioutil.WriteFile(newPasswd+".tar", c, 0644)
	if err != nil {
		log.Println(err)
	}
	err = untar(newPasswd+".tar", cpath)
	if err != nil {
		log.Println(err)
	}
	err = os.Remove(newPasswd + ".tar")
	if err != nil {
		log.Println(err)
	}

	return nil
}

// untar a tarball to a location
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

// uidReplace replaces image uid w/ specified uid in new passwd file
func uidReplace(findS string, replaceS string, lines []string, newPasswd string) {
	// find/replace w/ new uid
	for i, line := range lines {
		if strings.Contains(line, findS) {
			lines[i] = strings.Replace(lines[i], findS, replaceS, -1)
			check = lines[i]
		}
	}
	output := strings.Join(lines, "\n")
	err := ioutil.WriteFile(newPasswd, []byte(output), 0644)
	if err != nil {
		log.Println(err)
	}

	log.Printf("passwd entry replaced w/ '%s' @ %s", check, newPasswd)
	return
}

// mountPasswd bind mounts new passwd into container
func mountPasswd(id string, username string, imageUser string, useruid string, newPasswd string) {
	// modify the jsonFile2 directly... add /etc/passwd bind mount
	//  containerNewMount := &containerJSON.MountPoints{
	//		"/etc/passwd": {
	//			"Source":      newPasswd,
	//			"Destination": "/etc/passwd",
	//			"RW":          true,
	//			"Name":        "",
	//			"Driver":      "",
	//			"Relabel":     "Z",
	//			"Propagation": "rprivate",
	//			"Named":       	lse,
	//			"ID":          "",
	//		},
	//	}

	//	configFileName               = "config.v2.json"
	// https://github.com/docker/docker/blob/v1.12.5/libcontainerd/client.go
	// https://github.com/docker/docker/blob/v1.12.5/libcontainerd/client_linux.go
	// https://github.com/docker/docker/blob/v1.12.5/libcontainerd/container.go
	// https://github.com/docker/docker/tree/v1.12.5/libcontainerd
	//func (ctr *container) spec() (*specs.Spec, error) {
	//	dt, err := ioutil.ReadFile(filepath.Join(ctr.dir, configFilename))
	//	if err != nil {
	//		return nil, err
	//	}
	//	if err := json.Unmarshal(dt, &spec); err != nil {
	//		return nil, err
	//	}
	//	return &spec, nil
	//}

	log.Printf("%s mount complete", pfile)
	return
}
