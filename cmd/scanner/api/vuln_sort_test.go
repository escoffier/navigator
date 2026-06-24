package api

import (
	"math/rand"
	"sort"
	"testing"
)

// 验证: SortScore 相同时排序顺序确定、可重复(修复分页翻页重复/遗漏问题)。
func TestVulnPKGsDeterministicOrder(t *testing.T) {
	base := []VulnPKG{
		{UniqueID: 30, SortScore: 0},
		{UniqueID: 10, SortScore: 0},
		{UniqueID: 20, SortScore: 0},
		{UniqueID: 5, SortScore: 100},
		{UniqueID: 99, SortScore: 100},
		{UniqueID: 7, SortScore: 50},
	}

	want := func() []uint64 {
		s := append([]VulnPKG(nil), base...)
		sort.Sort(VulnPKGs(s))
		ids := make([]uint64, len(s))
		for i := range s {
			ids[i] = s[i].UniqueID
		}
		return ids
	}()

	// 期望: SortScore 降序; 同分按 UniqueID 升序
	expect := []uint64{5, 99, 7, 10, 20, 30}
	if !equalU64(want, expect) {
		t.Fatalf("unexpected order: got %v want %v", want, expect)
	}

	// 多次打乱输入,排序结果必须每次完全一致
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 50; iter++ {
		s := append([]VulnPKG(nil), base...)
		rng.Shuffle(len(s), func(a, b int) { s[a], s[b] = s[b], s[a] })
		sort.Sort(VulnPKGs(s))
		got := make([]uint64, len(s))
		for i := range s {
			got[i] = s[i].UniqueID
		}
		if !equalU64(got, want) {
			t.Fatalf("iter %d: non-deterministic order: got %v want %v", iter, got, want)
		}
	}
}

func TestVulnLanguagesDeterministicOrder(t *testing.T) {
	base := []*VulnLanguage{
		{LanguageName: "go", LanguagePath: "/b", SortScore: 0},
		{LanguageName: "go", LanguagePath: "/a", SortScore: 0},
		{LanguageName: "java", LanguagePath: "/a", SortScore: 0},
		{LanguageName: "python", LanguagePath: "/x", SortScore: 100},
	}
	want := sortLangIDs(base)
	expect := []string{"python|/x", "go|/a", "go|/b", "java|/a"}
	if !equalStr(want, expect) {
		t.Fatalf("unexpected order: got %v want %v", want, expect)
	}
	rng := rand.New(rand.NewSource(2))
	for iter := 0; iter < 50; iter++ {
		s := append([]*VulnLanguage(nil), base...)
		rng.Shuffle(len(s), func(a, b int) { s[a], s[b] = s[b], s[a] })
		if got := sortLangIDs(s); !equalStr(got, want) {
			t.Fatalf("iter %d: non-deterministic order: got %v want %v", iter, got, want)
		}
	}
}

func TestVulnGobinariesDeterministicOrder(t *testing.T) {
	base := []*VulnGobinary{
		{GoName: "b", GoPath: "/2", SortScore: 0},
		{GoName: "b", GoPath: "/1", SortScore: 0},
		{GoName: "a", GoPath: "/1", SortScore: 0},
		{GoName: "z", GoPath: "/9", SortScore: 100},
	}
	want := sortGoIDs(base)
	expect := []string{"z|/9", "a|/1", "b|/1", "b|/2"}
	if !equalStr(want, expect) {
		t.Fatalf("unexpected order: got %v want %v", want, expect)
	}
	rng := rand.New(rand.NewSource(3))
	for iter := 0; iter < 50; iter++ {
		s := append([]*VulnGobinary(nil), base...)
		rng.Shuffle(len(s), func(a, b int) { s[a], s[b] = s[b], s[a] })
		if got := sortGoIDs(s); !equalStr(got, want) {
			t.Fatalf("iter %d: non-deterministic order: got %v want %v", iter, got, want)
		}
	}
}

func TestVulnFramesDeterministicOrder(t *testing.T) {
	base := []*VulnFrame{
		{Frame: "spring", SortScore: 0},
		{Frame: "django", SortScore: 0},
		{Frame: "rails", SortScore: 0},
		{Frame: "express", SortScore: 100},
	}
	want := sortFrameIDs(base)
	expect := []string{"express", "django", "rails", "spring"}
	if !equalStr(want, expect) {
		t.Fatalf("unexpected order: got %v want %v", want, expect)
	}
	rng := rand.New(rand.NewSource(4))
	for iter := 0; iter < 50; iter++ {
		s := append([]*VulnFrame(nil), base...)
		rng.Shuffle(len(s), func(a, b int) { s[a], s[b] = s[b], s[a] })
		if got := sortFrameIDs(s); !equalStr(got, want) {
			t.Fatalf("iter %d: non-deterministic order: got %v want %v", iter, got, want)
		}
	}
}

func sortLangIDs(in []*VulnLanguage) []string {
	s := append([]*VulnLanguage(nil), in...)
	sort.Sort(VulnLanguages(s))
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i].LanguageName + "|" + s[i].LanguagePath
	}
	return out
}

func sortGoIDs(in []*VulnGobinary) []string {
	s := append([]*VulnGobinary(nil), in...)
	sort.Sort(VulnGobinaries(s))
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i].GoName + "|" + s[i].GoPath
	}
	return out
}

func sortFrameIDs(in []*VulnFrame) []string {
	s := append([]*VulnFrame(nil), in...)
	sort.Sort(VulnFrames(s))
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i].Frame
	}
	return out
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
