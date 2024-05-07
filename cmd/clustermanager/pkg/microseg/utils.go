package microseg

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/davecgh/go-spew/spew"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	v1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
)

func AddressMaptoSlice(addressMap map[string][]v1alpha1.Address) []v1alpha1.Address {
	ads := make([]v1alpha1.Address, 0, len(addressMap))
	for _, address := range addressMap {
		ads = append(ads, address...)
	}
	AddressSlice(ads).Sort()
	return ads
}

func CompareLabels(m1, m2 map[string]string) bool {
	set1 := labels.Set(m1)
	set2 := labels.Set(m2)
	return set1.String() == set2.String()
}

func podsUnion(p1s, p2s []*corev1.Pod) []*corev1.Pod {
	var pods, result []*corev1.Pod
	pods = append(pods, p1s...)
	pods = append(pods, p2s...)

	podMap := make(map[string]struct{})

	for _, p := range pods {
		key, _ := KeyFunc(p)
		if _, exist := podMap[key]; !exist {
			podMap[key] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}

func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}

func podKey(pod *corev1.Pod) string {
	strSet := sets.NewString(pod.Namespace)
	for k, v := range pod.Labels {
		strSet.Insert(fmt.Sprintf("%s/%s", k, v))
	}

	str := strSet.List()
	hasher := md5.New()
	DeepHashObject(hasher, str)
	// return hex.EncodeToString(hasher.Sum(nil)[0:])
	logging.Get().Info().Msgf("matching pod hash %s ", str)
	hashValue := hex.EncodeToString(hasher.Sum(nil))
	return hashValue[:16]
}

func dedupPods(ps []*corev1.Pod) []*corev1.Pod {
	var result []*corev1.Pod
	podMap := make(map[string]struct{})
	for _, p := range ps {
		key := podKey(p)
		if _, exist := podMap[key]; !exist {
			podMap[key] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}

// func dedupNodeRules(ps []v1alpha1.NodeRule) []v1alpha1.NodeRule {
// 	var result []v1alpha1.NodeRule
// 	ruleMap := make(map[v1alpha1.NodeRule]struct{})
// 	for _, p := range ps {
// 		key := podKey(p)
// 		if _, exist := podMap[key]; !exist {
// 			podMap[key] = struct{}{}
// 			result = append(result, p)
// 		}
// 	}
// 	return result
// }
