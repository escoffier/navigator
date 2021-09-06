package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	// The directories to load profiles from.
	dirs []string
	poll = flag.Duration("poll", -1, "Poll the directories for new profiles with this interval. Values < 0 disable polling, and exit after loading the profiles.")
)

type ProfileRoot struct {
	rootDir string
	kind    model.SecurityKind
}

const (
	parser              = "apparmor_parser"
	complain            = "aa-complain"
	enforce             = "aa-enforce"
	apparmorfs          = "/sys/kernel/security/apparmor"
	apparmorDir         = "/etc/apparmor.d"
	commandWhitelistDir = "/var/lib/kubelet/cw"
	seccompDir          = "/var/lib/kubelet/seccomp"
)

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get k8s client")
		return
	}

	profileRoots := []ProfileRoot{
		{
			rootDir: filepath.Join(apparmorDir, "tensorsec"),
			kind:    model.SecurityKindApparmor,
		},
		{
			rootDir: filepath.Join(commandWhitelistDir, "tensorsec"),
			kind:    model.SecurityKindCommandWhitelist,
		},
		{
			rootDir: filepath.Join(seccompDir, "tensorsec"),
			kind:    model.SecurityKindSeccomp,
		},
	}

	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	secProfilesContainerConfigMap := os.Getenv("SEC_PROFILES_CONTAINER_CONFIGMAP")

	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fmt.Sprintf("metadata.name=%s", secProfilesContainerConfigMap)
	}

	for _, profileRoot := range profileRoots {
		if _, err = os.Stat(path.Dir(profileRoot.rootDir)); os.IsNotExist(err) {
			os.Mkdir(path.Dir(profileRoot.rootDir), os.FileMode(0644))
		}
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("dir", profileRoot.rootDir).Msg("Failed to create directory for profiles")
			return
		}
		if _, err = os.Stat(profileRoot.rootDir); os.IsNotExist(err) {
			os.Mkdir(profileRoot.rootDir, os.FileMode(0644))
		}
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("dir", profileRoot.rootDir).Msg("Failed to create directory for profiles")
			return
		}
	}

	watchlist := cache.NewFilteredListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		string(corev1.ResourceConfigMaps),
		myNamespace,
		optionsModifier,
	)
	_, controller := cache.NewInformer(
		watchlist,
		&corev1.ConfigMap{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				configmap, ok := obj.(*corev1.ConfigMap)
				if !ok {
					logging.GetLogger().Error().Str("configmap", fmt.Sprintf("%+v\n", obj)).Msg("Failed to cast to *corev1.ConfigMap")
					return
				}
				existingProfiles := make(map[string]bool)
				if configmap.Data == nil {
					configmap.Data = make(map[string]string)
				}
				for k, v := range configmap.Data {
					existingProfiles[k] = true
					fmt.Println(k)
					kSplit := strings.Split(k, "-")
					kind := model.SecurityKind(strings.Join(kSplit[:len(kSplit)-1], "-"))
					profileName := k
					var profilePath string
					if kind == model.SecurityKindApparmor {
						profilePath = filepath.Join(apparmorDir, "tensorsec", filepath.Base(profileName))
					} else if kind == model.SecurityKindCommandWhitelist {
						profilePath = filepath.Join(commandWhitelistDir, "tensorsec", filepath.Base(profileName))
					} else if kind == model.SecurityKindSeccomp {
						profilePath = filepath.Join(seccompDir, "tensorsec", filepath.Base(profileName))
					} else {
						logging.GetLogger().Error().Err(err).Str("kind", string(kind)).Msg("Unsupported profile kind")
						return
					}
					exists, err := checkIfProfileExists(profilePath)
					if err != nil {
						logging.GetLogger().Error().Err(err).Str("profile", k).Msg("Failed to check profile existence")
						return
					}
					vSplit := strings.Split(v, "\n")
					mode := vSplit[0]
					data := strings.Join(vSplit[1:], "\n")
					if !exists {
						err = createProfile(profilePath, data)
						logging.GetLogger().Info().Str("path", profilePath).Msg("Creating profile")
						if err != nil {
							logging.GetLogger().Error().Err(err).Msg("Failed to create profile")
							continue
						}
						if kind == model.SecurityKindApparmor {
							err = loadProfile(profilePath, model.SecurityMode(mode))
							logging.GetLogger().Info().Str("path", profilePath).Msg("Loading apparmor profile")
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to load profile")
								continue
							}
						}
						logging.GetLogger().Info().Str("path", profilePath).Msg("Profile created")
					} else {
						same, err := checkIfProfileUnchanged(profilePath, data)
						if err != nil {
							logging.GetLogger().Error().Err(err).Msg("Failed to check profile similarity")
							continue
						}
						if !same {
							if kind == model.SecurityKindApparmor {
								logging.GetLogger().Info().Str("path", profilePath).Msg("Unloading apparmor profile")
								err = unloadProfile(profilePath)
								if err != nil {
									logging.GetLogger().Error().Err(err).Msg("Failed to unload profile")
									continue
								}
							}
							logging.GetLogger().Info().Str("path", profilePath).Msg("Removing profile")
							err = removeProfile(profilePath)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to remove profile")
								continue
							}
							logging.GetLogger().Info().Str("path", profilePath).Msg("Creating profile")
							err = createProfile(profilePath, data)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to create profile")
								continue
							}
							if kind == model.SecurityKindApparmor {
								logging.GetLogger().Info().Str("path", profilePath).Msg("Loading apparmor profile")
								err = loadProfile(profilePath, model.SecurityMode(mode))
								if err != nil {
									logging.GetLogger().Error().Err(err).Msg("Failed to load profile")
									continue
								}
							}
							logging.GetLogger().Info().Str("path", profilePath).Msg("Profile created")
						}
					}
				}
				var files []string
				for _, profileRoot := range profileRoots {
					err := filepath.Walk(profileRoot.rootDir, func(path string, info os.FileInfo, err error) error {
						if path != profileRoot.rootDir {
							files = append(files, path)
						}
						return nil
					})
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to get existing profiles")
						return
					}
					for _, file := range files {
						fmt.Println("A")
						fmt.Println(fmt.Sprintf("%s-%s", profileRoot.kind, file))
						if _, ok := existingProfiles[fmt.Sprintf("%s-%s", profileRoot.kind, file)]; !ok {
							if profileRoot.kind == model.SecurityKindApparmor {
								logging.GetLogger().Info().Str("path", file).Msg("Unloading apparmor profile")
								err = unloadProfile(file)
								if err != nil {
									logging.GetLogger().Error().Err(err).Msg("Failed to unload profile")
									continue
								}
							}
							logging.GetLogger().Info().Str("path", file).Msg("Remove profile")
							err = removeProfile(file)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to remove profile")
								continue
							}
							logging.GetLogger().Info().Str("path", file).Msg("Profile removed")
						}
					}
				}
				return
			},
			DeleteFunc: func(obj interface{}) {
				var files []string
				for _, profileRoot := range profileRoots {
					err := filepath.Walk(profileRoot.rootDir, func(path string, info os.FileInfo, err error) error {
						if path != profileRoot.rootDir {
							files = append(files, path)
						}
						return nil
					})
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Failed to get existing profiles")
						return
					}
					for _, file := range files {
						if profileRoot.kind == model.SecurityKindApparmor {
							logging.GetLogger().Info().Str("path", file).Msg("Unloading apparmor profile")
							err = unloadProfile(file)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to unload profile")
								continue
							}
						}
						logging.GetLogger().Info().Str("path", file).Msg("Removing profile")
						err = removeProfile(file)
						if err != nil {
							logging.GetLogger().Error().Err(err).Msg("Failed to remove profile")
							continue
						}
						logging.GetLogger().Info().Str("path", file).Msg("Profile removed")
					}
				}
				return
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldconfigmap, ok := oldObj.(*corev1.ConfigMap)
				if !ok {
					logging.GetLogger().Error().Str("configmap", fmt.Sprintf("%+v\n", oldObj)).Msg("Failed to cast to *corev1.ConfigMap")
					return
				}
				if oldconfigmap.Data == nil {
					oldconfigmap.Data = make(map[string]string)
				}
				newconfigmap, ok := newObj.(*corev1.ConfigMap)
				if !ok {
					logging.GetLogger().Error().Err(err).Str("configmap", fmt.Sprintf("%+v\n", newObj)).Msg("Failed to cast to *corev1.ConfigMap")
					return
				}
				if newconfigmap.Data == nil {
					newconfigmap.Data = make(map[string]string)
				}
				for k, v := range oldconfigmap.Data {
					val, ok := newconfigmap.Data[k]
					kSplit := strings.Split(k, "-")
					kind := model.SecurityKind(strings.Join(kSplit[:len(kSplit)-1], "-"))
					profileName := k
					if !ok {
						var profilePath string
						if kind == model.SecurityKindApparmor {
							profilePath = filepath.Join(apparmorDir, "tensorsec", filepath.Base(profileName))
							logging.GetLogger().Info().Str("path", profilePath).Msg("Unloading apparmor profile")
							err = unloadProfile(profilePath)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to unload profile")
								continue
							}
						} else if kind == model.SecurityKindCommandWhitelist {
							profilePath = filepath.Join(commandWhitelistDir, "tensorsec", filepath.Base(profileName))
						} else if kind == model.SecurityKindSeccomp {
							profilePath = filepath.Join(seccompDir, "tensorsec", filepath.Base(profileName))
						} else {
							logging.GetLogger().Error().Err(err).Str("kind", string(kind)).Msg("Unsupported profile kind")
							return
						}
						logging.GetLogger().Info().Str("path", profilePath).Msg("Removing profile")
						err = removeProfile(profilePath)
						if err != nil {
							logging.GetLogger().Error().Err(err).Msg("Failed to remove profile")
							continue
						}
						logging.GetLogger().Info().Str("path", profilePath).Msg("Profile removed")
					} else {
						if v != val {
							vSplit := strings.Split(val, "\n")
							mode := vSplit[0]
							data := strings.Join(vSplit[1:], "\n")
							var profilePath string
							if kind == model.SecurityKindApparmor {
								profilePath = filepath.Join(apparmorDir, "tensorsec", filepath.Base(profileName))
								logging.GetLogger().Info().Str("path", profilePath).Msg("Unloading apparmor profile")
								err = unloadProfile(profilePath)
								if err != nil {
									logging.GetLogger().Error().Err(err).Msg("Failed to unload profile")
									continue
								}
							} else if kind == model.SecurityKindCommandWhitelist {
								profilePath = filepath.Join(commandWhitelistDir, "tensorsec", filepath.Base(profileName))
							} else if kind == model.SecurityKindSeccomp {
								profilePath = filepath.Join(seccompDir, "tensorsec", filepath.Base(profileName))
							} else {
								logging.GetLogger().Error().Err(err).Str("kind", string(kind)).Msg("Unsupported profile kind")
								return
							}
							logging.GetLogger().Info().Str("path", profilePath).Msg("Removing profile")
							err = removeProfile(profilePath)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to remove profile")
								continue
							}
							logging.GetLogger().Info().Str("path", profilePath).Msg("Creating profile")
							err = createProfile(profilePath, data)
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to create profile")
								continue
							}
							if kind == model.SecurityKindApparmor {
								logging.GetLogger().Info().Str("path", profilePath).Msg("Loading apparmor profile")
								err = loadProfile(profilePath, model.SecurityMode(mode))
								if err != nil {
									logging.GetLogger().Error().Err(err).Msg("Failed to load profile")
									continue
								}
							}
							logging.GetLogger().Info().Str("path", profilePath).Msg("Profile created")
						}
					}
				}
				for k, v := range newconfigmap.Data {
					vSplit := strings.Split(v, "\n")
					mode := vSplit[0]
					data := strings.Join(vSplit[1:], "\n")
					_, ok := oldconfigmap.Data[k]
					if !ok {
						kSplit := strings.Split(k, "-")
						kind := model.SecurityKind(strings.Join(kSplit[:len(kSplit)-1], "-"))
						profileName := k
						var profilePath string
						if kind == model.SecurityKindApparmor {
							profilePath = filepath.Join(apparmorDir, "tensorsec", filepath.Base(profileName))
						} else if kind == model.SecurityKindCommandWhitelist {
							profilePath = filepath.Join(commandWhitelistDir, "tensorsec", filepath.Base(profileName))
						} else if kind == model.SecurityKindSeccomp {
							profilePath = filepath.Join(seccompDir, "tensorsec", filepath.Base(profileName))
						} else {
							logging.GetLogger().Error().Err(err).Str("kind", string(kind)).Msg("Unsupported profile kind")
							return
						}
						logging.GetLogger().Info().Str("path", profilePath).Msg("Create profile")
						err = createProfile(profilePath, data)
						if err != nil {
							logging.GetLogger().Error().Err(err).Msg("Failed to create profile")
							continue
						}
						if kind == model.SecurityKindApparmor {
							logging.GetLogger().Info().Str("path", profilePath).Msg("Loading apparmor profile")
							err = loadProfile(profilePath, model.SecurityMode(mode))
							if err != nil {
								logging.GetLogger().Error().Err(err).Msg("Failed to load profile")
								continue
							}
						}
						logging.GetLogger().Info().Str("path", profilePath).Msg("Profile created")
					}
				}
				return
			},
		})
	stop := make(chan struct{})
	go controller.Run(stop)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	stop <- struct{}{}
	logrus.Info("received OS shutdown signal, shutting down security profiles loader gracefully...")
}

func checkIfProfileExists(src string) (bool, error) {
	var err error
	sourceFileStat, err := os.Stat(src)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", src)
	}
	return true, nil
}

func checkIfProfileUnchanged(src string, content string) (bool, error) {
	var err error
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return false, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", src)
	}

	one, err := ioutil.ReadFile(src)
	if err != nil {
		return false, err
	}
	same := bytes.Equal(one, []byte(content))

	return same, nil
}

func createProfile(dst string, content string) error {
	var err error

	f, err := os.Create(dst)

	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func loadProfile(dst string, mode model.SecurityMode) error {
	cmd := exec.Command(parser, "--verbose", dst)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	out, err := cmd.Output()
	logging.GetLogger().Info().Str("path", dst).Str("out", string(out)).Str("stderr", fmt.Sprintf("%v\n", stderr)).Msg("Loading profiles")
	if err != nil {
		return fmt.Errorf("error loading profiles from %s: %w", dst, err)
	}
	if mode == model.SecurityModeDetection {
		cmd = exec.Command(complain, dst)
		stderr = &bytes.Buffer{}
		cmd.Stderr = stderr
		out, err = cmd.Output()
		logging.GetLogger().Info().Str("path", dst).Str("out", string(out)).Str("stderr", fmt.Sprintf("%v\n", stderr)).Msg("Loading profile to complain mode")
		if err != nil {
			return fmt.Errorf("error loading profiles from %s: %w", dst, err)
		}
	} else if mode == model.SecurityModePrevention {
		cmd = exec.Command(enforce, dst)
		stderr = &bytes.Buffer{}
		cmd.Stderr = stderr
		out, err = cmd.Output()
		logging.GetLogger().Info().Str("path", dst).Str("out", string(out)).Str("stderr", fmt.Sprintf("%v\n", stderr)).Msg("Loading profile to enforce mode")
		if err != nil {
			return fmt.Errorf("error loading profiles from %s: %w", dst, err)
		}
	}
	return nil
}

func removeProfile(src string) error {
	var err error
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	err = os.Remove(src)
	return err
}

func unloadProfile(src string) error {
	var err error

	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	cmd := exec.Command(parser, "-R", src)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	out, err := cmd.Output()
	logging.GetLogger().Info().Str("path", src).Str("out", string(out)).Str("stderr", fmt.Sprintf("%v\n", stderr)).Msg("Unloading profiles")
	if err != nil {
		return fmt.Errorf("error unloading profiles from %s: %w", src, err)
	}
	return nil
}
