// +build linux

package main

import _ "github.com/opencontainers/runc/libcontainer/nsenter"

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/container"
	"github.com/opencontainers/runc/libcontainer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/tidwall/gjson"
	"github.com/vishvananda/netlink/nl"
	yaml "gopkg.in/yaml.v1"
)

const (
	config           = "/etc/oci-uid-hook.conf" // Config file for disabling hook
	dockerAPIversion = "1.24"                   // docker server api version
	pfile            = "/etc/passwd"            // passwd path in container
	ctxTimeout       = 10 * time.Second         // docker client timeout
	mountinfoFormat  = "%d %d %d:%d %s %s %s %s"
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
	hostCFile := fmt.Sprintf("%s/hostconfig.json", cpath)

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
			if err = UIDHook(command, containerJSON.Config.Image, state.ID, cpath, jsonFileData, newjsonFileData, configFile, newconfigFile, hostCFile); err != nil {
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

func checkErr(err error) {
	if err != nil {
		log.Println(err)
	}
}

// UIDHook for username recognition w/ arbitrary uid in the container
func UIDHook(command string, image string, id string, cpath string, jsonFile []byte, newjsonFile []byte, configFile string, newconfigFile string, hostCFile string) error {
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

	newPasswd := fmt.Sprintf("%s/passwd", cpath)
	if _, err := os.Stat(newPasswd); err == nil {
		pwcheck = true
	}
	// faster but less thorough?
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
			uidReplace(findS, replaceS, lines, newPasswd)
			mountPasswd(id, newPasswd, jsonFile, newjsonFile, configFile, newconfigFile, hostCFile)
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
	checkErr(err)

	log.Printf("passwd entry replaced w/ '%s' @ %s", check, newPasswd)
	return
}

// mountPasswd bind mounts new passwd into container
func mountPasswd(id string, newPasswd string, jsonFile []byte, newjsonFile []byte, configFile string, newconfigFile string, hostCFile string) {
	//sPid := C.int(state.Pid)
	//mntTest := C.enter_namespace(sPid)
	//mntTests := C.GoString(mntTest)
	//log.Printf(mntTests)
	return
}

type pid struct {
	Pid int `json:"Pid"`
}

// TestNsenterValidPaths is good
func TestNsenterValidPaths(t *testing.T) {
	args := []string{"nsenter-exec"}
	parent, child, err := newPipe()
	if err != nil {
		t.Fatalf("failed to create pipe %v", err)
	}

	namespaces := []string{
		// join pid ns of the current process
		fmt.Sprintf("pid:/proc/%d/ns/pid", os.Getpid()),
	}
	cmd := &exec.Cmd{
		Path:       os.Args[0],
		Args:       args,
		ExtraFiles: []*os.File{child},
		Env:        []string{"_LIBCONTAINER_INITPIPE=3"},
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("nsenter failed to start %v", err)
	}
	// write cloneFlags
	r := nl.NewNetlinkRequest(int(libcontainer.InitMsg), 0)
	r.AddData(&libcontainer.Int32msg{
		Type:  libcontainer.CloneFlagsAttr,
		Value: uint32(syscall.CLONE_NEWNET),
	})
	r.AddData(&libcontainer.Bytemsg{
		Type:  libcontainer.NsPathsAttr,
		Value: []byte(strings.Join(namespaces, ",")),
	})
	if _, err := io.Copy(parent, bytes.NewReader(r.Serialize())); err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(parent)
	var pid *pid

	if err := cmd.Wait(); err != nil {
		t.Fatalf("nsenter exits with a non-zero exit status")
	}
	if err := decoder.Decode(&pid); err != nil {
		dir, _ := ioutil.ReadDir(fmt.Sprintf("/proc/%d/ns", os.Getpid()))
		for _, d := range dir {
			t.Log(d.Name())
		}
		t.Fatalf("%v", err)
	}

	p, err := os.FindProcess(pid.Pid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	p.Wait()
}

func init() {
	if strings.HasPrefix(os.Args[0], "nsenter-") {
		os.Exit(0)
	}
	return
}

func newPipe() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}

	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}
