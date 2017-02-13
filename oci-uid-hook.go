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

	simplejson "github.com/bitly/go-simplejson"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/tidwall/gjson"
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
	state         State
	containerJSON ContainerJSON
	check         string
	username      string
	usercheck     bool
	mountcheck    bool
	//usergid string

	settings struct {
		Disabled bool `yaml:"disabled"`
	}
)

// State holds information about the runtime state of the container.
type State struct {
	// Version is the version of the specification that is supported.
	Version string `json:"ociVersion"`
	// ID is the container ID
	ID string `json:"id"`
	// Status is the runtime status of the container.
	Status string `json:"status"`
	// Pid is the process ID for the container process.
	Pid int `json:"pid"`
	// Bundle is the path to the container's bundle directory.
	BundlePath string `json:"bundlepath"`
	// Annotations are key values associated with the container.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ContainerJSON is newly used struct along with MountPoint
type ContainerJSON struct {
	*types.ContainerJSONBase
	Mount           []MountPoint `json:"mountpoints"`
	Config          *container.Config
	NetworkSettings *types.NetworkSettings
}

// MountPoint represents a mount point configuration inside the container.
type MountPoint struct {
	Type        mount.Type `json:",omitempty"`
	Source      string
	Destination string
	RW          bool
	Name        string
	Driver      string
	Relabel     string
	Propagation mount.Propagation
	Named       bool
	ID          string
}

// t is for
type t struct {
	Mounts specs.Mount `json:"mounts"`
}

func main() {
	os.Setenv("DOCKER_API_VERSION", dockerAPIversion)

	logwriter, err := syslog.New(syslog.LOG_NOTICE, "oci-uid-hook")
	if err == nil {
		log.SetOutput(logwriter)
	}

	// config file settings
	configf, err := os.Open(config)
	checkErr(err)
	data, err := ioutil.ReadAll(configf)
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
	if err := configf.Close(); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}

	command := os.Args[1]
	configFile := os.Args[2]
	cpath := path.Dir(configFile)

	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}

	newconfigFile := fmt.Sprintf("%s/config.json", state.BundlePath)
	// get additional container info

	jsonFile, err := os.Open(configFile)
	checkErr(err)
	jsonFileData, err := ioutil.ReadAll(jsonFile)
	checkErr(err)
	if err := jsonFile.Close(); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}

	newjsonFile, err := os.Open(newconfigFile)
	checkErr(err)
	newjsonFileData, err := ioutil.ReadAll(newjsonFile)
	checkErr(err)
	if err := newjsonFile.Close(); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}
	json.Unmarshal(jsonFileData, &containerJSON)
	// 	log.Printf(string(jsonFile))

	switch command {
	case "prestart":
		{
			if err = UIDHook(command, containerJSON.Config.Image, state.ID, cpath, jsonFileData, newjsonFileData, configFile, newconfigFile); err != nil {
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
func UIDHook(command string, image string, id string, cpath string, jsonFile []byte, newjsonFile []byte, configFile string, newconfigFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	cli, _ := client.NewEnvClient()

	// retrieve image user
	imageJSON, _, err := cli.ImageInspectWithRaw(ctx, image)
	checkErr(err)
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

	// check for existing /etc/passwd bind mount... bypass if exists.
	// more iterative approach below... better?
	pwMount := gjson.GetBytes(jsonFile, "MountPoints")
	pwMount.ForEach(func(key, value gjson.Result) bool {
		pwMountDest := gjson.Get(value.String(), "Destination")
		pwMountDest.ForEach(func(key, value2 gjson.Result) bool {
			if value2.String() == pfile {
				mountcheck = true
			}
			return true // keep iterating
		})
		return true // keep iterating
	})

	// faster but less thorough?
	// _, mountcheck := containerJSON.MountPoints[pfile]

	if mountcheck == true {
		log.Printf("hook bypassed: %s already mounted", pfile)
		return nil
	}

	// retrieve passwd file from container
	newPasswd := fmt.Sprintf("%s/passwd", cpath)
	// procPasswd := fmt.Sprintf("/proc/%d/root/etc/passwd", state.Pid)
	imageName := imageJSON.ID
	fileRetrieve(imageName, newPasswd, cpath)
	checkErr(err)

	pwFile, err := os.Open(newPasswd)
	checkErr(err)
	in, err := ioutil.ReadAll(pwFile)
	if err := pwFile.Close(); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}
	useruid := user
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
			mountPasswd(newPasswd, jsonFile, newjsonFile, configFile, newconfigFile)
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
	cfile, _, err := cli.CopyFromContainer(ctx, tcuid.ID, pfile)
	if err != nil {
		log.Println(err)
	}
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
	checkErr(err)
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
		checkErr(err)
		defer file.Close()
		_, err = io.Copy(file, tarReader)
		checkErr(err)
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
func mountPasswd(newPasswd string, jsonFile []byte, newjsonFile []byte, configFile string, newconfigFile string) {
	// modify the jsonFile2 directly... add /etc/passwd bind mount

	// !!!!!!!!!!!!!!!
	// config.v2.json configuration
	mount := map[string]MountPoint{
		pfile: MountPoint{
			Source:      newPasswd,
			Destination: pfile,
			RW:          true,
			Name:        "",
			Driver:      "",
			Relabel:     "Z",
			Propagation: "rprivate",
			Named:       false,
			ID:          "",
		},
	}

	mount3 := MountPoint{
		Source:      newPasswd,
		Destination: pfile,
		RW:          true,
		Name:        "",
		Driver:      "",
		Relabel:     "Z",
		Propagation: "rprivate",
		Named:       false,
		ID:          "",
	}
	pf, _ := json.Marshal(mount)
	js, _ := simplejson.NewJson(jsonFile)
	jsn, _ := simplejson.NewJson(pf)

	// unmarshal method
	json.Unmarshal(jsonFile, &containerJSON)
	test := append(containerJSON.Mount, mount3)

	// append new mountpoint to current ones
	newfile := &containerJSON
	newfile.Mount = test

	cjsonfinal, _ := json.Marshal(newfile)

	// current mountpoints mapping
	jsnMPs := js.Get("MountPoints")
	jsnMPm, _ := jsnMPs.Map()
	// new /etc/passwd bind mount mapping
	jsnm, _ := jsn.Map()
	// append new mountpoint to current ones
	jsnMPm[pfile] = jsnm[pfile]
	// current full config.v2.json mapping
	jsnMm, _ := js.Map()
	// append new combined mountpoints mapping to overall config
	jsnMm["MountPoints"] = jsnMPm
	jsonfinal, _ := json.Marshal(jsnMm)
	// write new config file to disk

	err := ioutil.WriteFile(configFile+".new", cjsonfinal, 0666)
	checkErr(err)
	err2 := ioutil.WriteFile(configFile+".new2", jsonfinal, 0666)
	checkErr(err2)
	err3 := ioutil.WriteFile(configFile+".orig", jsonFile, 0666)
	checkErr(err3)

	log.Printf("%v", string(cjsonfinal))
	log.Printf("%v", configFile)

	// !!!!!!!!!!!!!!!
	// config.json configuration
	mount2 := t{
		Mounts: specs.Mount{
			Destination: pfile,
			Type:        "bind",
			Source:      newPasswd,
			Options:     []string{"rbind", "rprivate"},
		},
	}

	// unmarshal method
	json.Unmarshal(newjsonFile, &spec)
	test2 := append(spec.Mounts, mount2.Mounts)

	// append new mountpoint to current ones
	newfile2 := &spec
	newfile2.Mounts = test2

	cjsonfinal2, _ := json.Marshal(newfile2)

	// write new config file to disk
	cerr := ioutil.WriteFile(newconfigFile, cjsonfinal2, 0644)
	checkErr(cerr)

	log.Printf("%v", newconfigFile)
	log.Printf("%s bind mount complete", pfile)
	return
}

func checkErr(err error) {
	if err != nil {
		log.Println(err)
	}
}
