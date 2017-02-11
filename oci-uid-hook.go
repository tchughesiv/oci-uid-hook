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

// CONFIG uid hook configuration
const (
	CONFIG           = "/etc/oci-uid-hook.conf" // Config file for disabling hook
	dockerAPIversion = "1.24"                   // docker server api version
	pfile            = "/etc/passwd"            // passwd path in container
	ctxTimeout       = 10 * time.Second         // docker client timeout
)

var spec specs.Spec
var state specs.State
var containerJSON ContainerJSON
var settings struct {
	Disabled bool `yaml:"disabled"`
}

//	configFileName               = "config.v2.json"
// https://github.com/docker/docker/blob/v1.12.5/libcontainerd/client.go
// https://github.com/docker/docker/blob/v1.12.5/libcontainerd/client_linux.go
// https://github.com/docker/docker/blob/v1.12.5/libcontainerd/container.go
// https://github.com/docker/docker/tree/v1.12.5/libcontainerd
//func (ctr *container) spec() (*specs.Spec, error) {
//	var spec specs.Spec
//	dt, err := ioutil.ReadFile(filepath.Join(ctr.dir, configFilename))
//	if err != nil {
//		return nil, err
//	}
//	if err := json.Unmarshal(dt, &spec); err != nil {
//		return nil, err
//	}
//	return &spec, nil
//}

func main() {
	os.Setenv("DOCKER_API_VERSION", dockerAPIversion)

	logwriter, err := syslog.New(syslog.LOG_NOTICE, "oci-uid-hook")
	if err == nil {
		log.SetOutput(logwriter)
	}

	// config file settings
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

	// newconfigFile := fmt.Sprintf("%s/config.json", state.BundlePath)
	// procPasswd := fmt.Sprintf("/proc/%d/root/etc/passwd", state.Pid)
	configFile := os.Args[2]
	command := os.Args[1]
	cpath := path.Dir(configFile)
	newPasswd := fmt.Sprintf("%s/passwd", cpath)

	// get additional container info
	jsonFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalln(err)
	}
	json.Unmarshal(jsonFile, &containerJSON)
	ugidresult := strings.Split(containerJSON.Config.User, ":")
	user := ugidresult[0]
	pwMount := containerJSON.MountPoints.MountPoint.Destination

	switch command {
	case "prestart":
		{
			// check for existing /etc/passwd bind mount... bypass if exists
			if pwMount != "" {
				log.Printf("Hook bypassed: /etc/passwd already bind mounted")
				return
			}

			log.Printf("%s %s", command, state.ID)
			if err = UIDHook(containerJSON.Config.Image, state.ID, user, cpath, newPasswd); err != nil {
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
func UIDHook(image string, id string, user string, cpath string, newPasswd string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	cli, _ := client.NewEnvClient()

	// retrieve image user
	imageJSON, imageOUT, err := cli.ImageInspectWithRaw(ctx, image)
	if err != nil {
		log.Fatalln(err)
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
	fileRetrieve(imageName, newPasswd, cpath)
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
			log.Printf("hook engaged: %s", newPasswd)
			replace(findS, replaceS, lines, newPasswd)
			mountConfig(id, username, imageUser, useruid, newPasswd)
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
		log.Fatalln(err)
	}
	cfile, stat, err := cli.CopyFromContainer(ctx, tcuid.ID, pfile)
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
		//	RemoveVolumes: true,
		Force: true,
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

	log.Printf("passwd entry replaced w/: '%s'", check)
	return
}

func mountConfig(id string, username string, imageUser string, useruid string, newPasswd string) {
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
	//			"Named":       false,
	//			"ID":          "",
	//		},
	//	}

	log.Printf("passwd file mount complete")
	return
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

// ContainerJSON is newly used struct along with MountPoint
type ContainerJSON struct {
	*types.ContainerJSONBase
	MountPoints MountPointData
	Config      *container.Config
}

// MountPointData represents a mount point configuration inside the container.
// This is used for reporting the mountpoints in use by a container.
type MountPointData struct {
	MountPoint types.MountPoint `json:"/etc/passwd"`
}
