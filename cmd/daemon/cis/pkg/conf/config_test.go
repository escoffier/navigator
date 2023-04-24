package conf

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var (
	g      string
	e      []error
	eIndex int
)

func fakeps(proc string) string {
	return g
}

func fakestat(file string) (os.FileInfo, error) {
	err := e[eIndex]
	eIndex++
	return nil, err
}

func TestVerifyBin(t *testing.T) {
	cases := []struct {
		proc  string
		psOut string
		exp   bool
	}{
		{proc: "single", psOut: "single", exp: true},
		{proc: "single", psOut: "", exp: false},
		{proc: "two words", psOut: "two words", exp: true},
		{proc: "two words", psOut: "", exp: false},
		{proc: "cmd", psOut: "cmd param1 param2", exp: true},
		{proc: "cmd param", psOut: "cmd param1 param2", exp: true},
		{proc: "cmd param", psOut: "cmd", exp: false},
		{proc: "cmd", psOut: "cmd x \ncmd y", exp: true},
		{proc: "cmd y", psOut: "cmd x \ncmd y", exp: true},
		{proc: "cmd", psOut: "/usr/bin/cmd", exp: true},
		{proc: "cmd", psOut: "kube-cmd", exp: false},
		{proc: "cmd", psOut: "/usr/bin/kube-cmd", exp: false},
	}

	psFunc = fakeps
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			g = c.psOut
			v := verifyBin(c.proc)
			if v != c.exp {
				t.Fatalf("Expected %v got %v", c.exp, v)
			}
		})
	}
}

func TestFindConfigFile(t *testing.T) {
	cases := []struct {
		input       []string
		statResults []error
		exp         string
	}{
		{input: []string{"myfile"}, statResults: []error{nil}, exp: "myfile"},
		{input: []string{"thisfile", "thatfile"}, statResults: []error{os.ErrNotExist, nil}, exp: "thatfile"},
		{input: []string{"thisfile", "thatfile"}, statResults: []error{os.ErrNotExist, os.ErrNotExist}, exp: ""},
	}

	statFunc = fakestat
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			e = c.statResults
			eIndex = 0
			conf := FindConfigFile(c.input)
			if conf != c.exp {
				t.Fatalf("Got %s expected %s", conf, c.exp)
			}
		})
	}
}

func TestMakeSubsitutions(t *testing.T) {
	cases := []struct {
		input        string
		subst        map[string]string
		exp          string
		expectedSubs []string
	}{
		{input: "Replace $thisbin", subst: map[string]string{"this": "that"}, exp: "Replace that", expectedSubs: []string{"that"}},
		{input: "Replace $thisbin", subst: map[string]string{"this": "that", "here": "there"}, exp: "Replace that", expectedSubs: []string{"that"}},
		{input: "Replace $thisbin and $herebin", subst: map[string]string{"this": "that", "here": "there"}, exp: "Replace that and there", expectedSubs: []string{"that", "there"}},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			s, subs := MakeSubstitutions(c.input, "bin", c.subst)
			if s != c.exp {
				t.Fatalf("Got %s expected %s", s, c.exp)
			}
			sort.Strings(subs)
			assert.Equal(t, c.expectedSubs, subs)
		})
	}
}

func TestMultiWordReplace(t *testing.T) {
	cases := []struct {
		input   string
		sub     string
		subname string
		output  string
	}{
		{input: "Here's a file with no substitutions", sub: "blah", subname: "blah", output: "Here's a file with no substitutions"},
		{input: "Here's a file with a substitution", sub: "blah", subname: "substitution", output: "Here's a file with a blah"},
		{input: "Here's a file with multi-word substitutions", sub: "multi word", subname: "multi-word", output: "Here's a file with 'multi word' substitutions"},
		{input: "Here's a file with several several substitutions several", sub: "blah", subname: "several", output: "Here's a file with blah blah substitutions blah"},
	}
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			s := multiWordReplace(c.input, c.subname, c.sub)
			if s != c.output {
				t.Fatalf("Expected %s got %s", c.output, s)
			}
		})
	}
}

func TestFindExecutable(t *testing.T) {
	cases := []struct {
		candidates []string // list of executables we'd consider
		psOut      string   // fake output from ps
		exp        string   // the one we expect to find in the (fake) ps output
		expErr     bool
	}{
		{candidates: []string{"one", "two", "three"}, psOut: "two", exp: "two"},
		{candidates: []string{"one", "two", "three"}, psOut: "two three", exp: "two"},
		{candidates: []string{"one double", "two double", "three double"}, psOut: "two double is running", exp: "two double"},
		{candidates: []string{"one", "two", "three"}, psOut: "blah", expErr: true},
		{candidates: []string{"one double", "two double", "three double"}, psOut: "two", expErr: true},
		{candidates: []string{"apiserver", "kube-apiserver"}, psOut: "kube-apiserver", exp: "kube-apiserver"},
		{candidates: []string{"apiserver", "kube-apiserver", "hyperkube-apiserver"}, psOut: "kube-apiserver", exp: "kube-apiserver"},
	}

	psFunc = fakeps
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			g = c.psOut
			e, err := FindExecutable(c.candidates)
			if e != c.exp {
				t.Fatalf("Expected %v got %v", c.exp, e)
			}

			if err == nil && c.expErr {
				t.Fatalf("Expected error")
			}

			if err != nil && !c.expErr {
				t.Fatalf("Didn't expect error: %v", err)
			}
		})
	}
}

func TestGetConfigFiles(t *testing.T) {
	cases := []struct {
		config      map[string]interface{}
		exp         map[string]string
		statResults []error
	}{
		{
			config:      map[string]interface{}{"components": []string{"apiserver"}, "apiserver": map[string]interface{}{"confs": []string{"apiserver", "kube-apiserver"}}},
			statResults: []error{os.ErrNotExist, nil},
			exp:         map[string]string{"apiserver": "kube-apiserver"},
		},
		{
			// Component "thing" isn't included in the list of components
			config: map[string]interface{}{
				"components": []string{"apiserver"},
				"apiserver":  map[string]interface{}{"confs": []string{"apiserver", "kube-apiserver"}},
				"thing":      map[string]interface{}{"confs": []string{"/my/file/thing"}},
			},
			statResults: []error{os.ErrNotExist, nil},
			exp:         map[string]string{"apiserver": "kube-apiserver"},
		},
		{
			// More than one component
			config: map[string]interface{}{
				"components": []string{"apiserver", "thing"},
				"apiserver":  map[string]interface{}{"confs": []string{"apiserver", "kube-apiserver"}},
				"thing":      map[string]interface{}{"confs": []string{"/my/file/thing"}},
			},
			statResults: []error{os.ErrNotExist, nil, nil},
			exp:         map[string]string{"apiserver": "kube-apiserver", "thing": "/my/file/thing"},
		},
		{
			// Default thing to specified default config
			config: map[string]interface{}{
				"components": []string{"apiserver", "thing"},
				"apiserver":  map[string]interface{}{"confs": []string{"apiserver", "kube-apiserver"}},
				"thing":      map[string]interface{}{"confs": []string{"/my/file/thing"}, "defaultconf": "another/thing"},
			},
			statResults: []error{os.ErrNotExist, nil, os.ErrNotExist},
			exp:         map[string]string{"apiserver": "kube-apiserver", "thing": "another/thing"},
		},
		{
			// Default thing to component name
			config: map[string]interface{}{
				"components": []string{"apiserver", "thing"},
				"apiserver":  map[string]interface{}{"confs": []string{"apiserver", "kube-apiserver"}},
				"thing":      map[string]interface{}{"confs": []string{"/my/file/thing"}},
			},
			statResults: []error{os.ErrNotExist, nil, os.ErrNotExist},
			exp:         map[string]string{"apiserver": "kube-apiserver", "thing": "thing"},
		},
	}

	v := viper.New()
	statFunc = fakestat

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			for k, val := range c.config {
				v.Set(k, val)
			}
			e = c.statResults
			eIndex = 0

			m := getFiles(v, "config")
			if !reflect.DeepEqual(m, c.exp) {
				t.Fatalf("Got %v\nExpected %v", m, c.exp)
			}
		})
	}
}

func TestGetConfigFilePath(t *testing.T) {
	var err error
	cfgDir, err := os.MkdirTemp("", "kube-bench-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory")
	}
	defer os.RemoveAll(cfgDir)
	d := filepath.Join(cfgDir, "cis-1.4")
	err = os.Mkdir(d, 0766)
	if err != nil {
		t.Fatalf("Failed to create temp dir")
	}
	err = os.WriteFile(filepath.Join(d, "master.yaml"), []byte("hello world"), 0666)
	if err != nil {
		t.Logf("Failed to create temp file")
	}

	cases := []struct {
		benchmarkVersion string
		succeed          bool
		exp              string
	}{
		{benchmarkVersion: "cis-1.4", succeed: true, exp: d},
		{benchmarkVersion: "cis-1.5", succeed: false, exp: ""},
		{benchmarkVersion: "1.1", succeed: false, exp: ""},
	}

	for _, c := range cases {
		t.Run(c.benchmarkVersion, func(t *testing.T) {
			path, err := GetConfigFilePath(c.benchmarkVersion, cfgDir, "/master.yaml")
			if c.succeed {
				if err != nil {
					t.Fatalf("Error %v", err)
				}
				if path != c.exp {
					t.Fatalf("Got %s expected %s", path, c.exp)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected Error, but none")
				}
			}
		})
	}
}

func TestLoadVersionMapping(t *testing.T) {
	setDefault := func(v *viper.Viper, key string, value interface{}) *viper.Viper {
		v.SetDefault(key, value)
		return v
	}

	viperWithData, err := loadConfigForTest()
	if err != nil {
		t.Fatalf("Unable to load config file %v", err)
	}

	cases := []struct {
		n       string
		v       *viper.Viper
		succeed bool
	}{
		{n: "empty", v: viper.New(), succeed: false},
		{
			n:       "novals",
			v:       setDefault(viper.New(), "version_mapping", "novals"),
			succeed: false,
		},
		{
			n:       "good",
			v:       viperWithData,
			succeed: true,
		},
	}
	for _, c := range cases {
		rv, err := LoadVersionMapping(c.v)
		if c.succeed {
			if err != nil {
				t.Errorf("[%q]-Unexpected error: %v", c.n, err)
			}

			if len(rv) == 0 {
				t.Errorf("[%q]-missing mapping value", c.n)
			}
		} else {
			if err == nil {
				t.Errorf("[%q]-Expected error but got none", c.n)
			}
		}
	}
}
