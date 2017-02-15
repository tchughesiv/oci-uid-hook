// +build linux
// example container runtime - this will trigger the hook
//    docker run -du 10001 tomaskral/nonroot-nginx
// these would NOT trigger the hook
//    docker run -du root tomaskral/nonroot-nginx
//    docker run -du 0 tomaskral/nonroot-nginx
//    docker run -du 10001 -v /tmp/passwd:/etc/passwd:Z tomaskral/nonroot-nginx

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
	"syscall"
	"time"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/container"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/tidwall/gjson"
	yaml "gopkg.in/yaml.v1"
)

const (
	dockerAPIversion = "1.24"                   // docker server api version
	config           = "/etc/oci-uid-hook.conf" // Config file for disabling hook
	pfile            = "/etc/passwd"            // passwd path in container
	ctxTimeout       = 10 * time.Second         // docker client timeout
)

var (
	state         specs.State
	containerJSON types.ContainerJSON
	check         string
	username      string
	usercheck     bool
	mountcheck    bool
	pwcheck       bool
	//usergid string

	settings struct {
		Disabled bool `yaml:"disabled"`
	}
)

func checkErr(err error) {
	if err != nil {
		log.Println(err)
	}
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

	// get additional container info
	jsonFile, err := os.Open(configFile)
	checkErr(err)
	jsonFileData, err := ioutil.ReadAll(jsonFile)
	checkErr(err)
	if err := jsonFile.Close(); err != nil {
		log.Printf("UIDHook Failed %v", err.Error())
	}
	json.Unmarshal(jsonFileData, &containerJSON)
	// 	log.Printf(string(jsonFile))

	switch command {
	case "prestart":
		{
			UIDHook(command, containerJSON.Config.Image, state.ID, cpath, jsonFileData, configFile)
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
func UIDHook(command string, image string, id string, cpath string, jsonFile []byte, configFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	cli, _ := client.NewEnvClient()

	// retrieve image user
	imageJSON, _, err := cli.ImageInspectWithRaw(ctx, image, false)
	checkErr(err)
	imageUser := imageJSON.Config.User
	ugidresult := strings.Split(containerJSON.Config.User, ":")
	user := ugidresult[0]

	// check if container user matches image user
	if eq := strings.Compare(imageUser, user); eq == 0 {
		return nil
	}

	// hook won't trigger if a user isn't specified in the image, so root assigned.
	// Should we assume root as below? what about scratch images? add logic there?
	if imageUser == "" {
		imageUser = "0"
	}
	// check if user is an integer
	if _, err := strconv.Atoi(user); err != nil {
		return nil
	}
	log.Printf("%s %s", command, state.ID)

	// check for existing /etc/passwd bind mount... bypass if exists.
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

	newPasswd := fmt.Sprintf("%s/passwd", cpath)
	if _, err := os.Stat(newPasswd); err == nil {
		pwcheck = true
	}
	// faster approach but less thorough?
	// _, mountcheck := containerJSON.MountPoints[pfile]

	if mountcheck == true {
		log.Printf("hook bypassed: %s already mounted", pfile)
		return nil
	}

	// add check for passwd file later and logic
	//if mountcheck != true {
	//}

	// retrieve passwd file from container
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
			output := uidReplace(findS, replaceS, lines, newPasswd)
			mountPasswd(id, newPasswd, jsonFile, configFile, output)
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
	checkErr(err)
	cfile, _, err := cli.CopyFromContainer(ctx, tcuid.ID, pfile)
	checkErr(err)
	c, err := ioutil.ReadAll(cfile)
	checkErr(err)
	cfile.Close()
	crm := cli.ContainerRemove(ctx, tcuid.ID, types.ContainerRemoveOptions{
		//	RemoveVolumes: true,
		Force: true,
	})
	checkErr(crm)

	// create copy of passwd file in cpath
	err = ioutil.WriteFile(newPasswd+".tar", c, 0644)
	checkErr(err)
	err = untar(newPasswd+".tar", cpath)
	checkErr(err)
	err = os.Remove(newPasswd + ".tar")
	checkErr(err)

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
func uidReplace(findS string, replaceS string, lines []string, newPasswd string) string {
	// find/replace w/ new uid
	for i, line := range lines {
		if strings.Contains(line, findS) {
			lines[i] = strings.Replace(lines[i], findS, replaceS, -1)
			check = lines[i]
		}
	}
	output := strings.Join(lines, "\n")
	err := ioutil.WriteFile(newPasswd, []byte(output), 0644)
	checkErr(err)

	log.Printf("passwd entry replaced w/ '%s' @ %s", check, newPasswd)
	return output
}

// mountPasswd bind mounts new passwd into container
func mountPasswd(id string, newPasswd string, jsonFile []byte, configFile string, output string) error {
	// likely need to join ns and bind mount directly
	// testing
	ProcNS := fmt.Sprintf("/proc/%d/ns", state.Pid)
	ProcPW := fmt.Sprintf("/proc/%d/etc/passwd", state.Pid)

	namespaces := []string{"ipc", "uts", "net", "pid", "mnt"}
	for i := range namespaces {
		fd, _ := syscall.Open(filepath.Join(ProcNS, namespaces[i]), syscall.O_RDONLY, 0644)
		err, _, msg := syscall.RawSyscall(308, uintptr(fd), 0, 0) // 308 == setns
		if err != 0 {
			log.Println("setns on", namespaces[i], "namespace failed:", msg)
		} else {
			log.Println("setns on", namespaces[i], "namespace succeeded")
		}

	}

	// factory, err := libcontainer.New("")
	// Container, err := factory.Load(state.ID)
	// checkErr(err)
	// test := Container.ID()
	// test := os.Getenv("_LIBCONTAINER_INITPIPE")
	log.Printf("To test uid-hook manually, execute these in order -")
	log.Printf("   $ docker exec %s id", state.ID)
	log.Printf("   $ cp -p %s %s", newPasswd, ProcPW)
	log.Printf("   $ docker exec %s id", state.ID)
	log.Printf("   $ docker exec %s ps -f", state.ID)
	return nil
}
