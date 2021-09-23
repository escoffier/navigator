package util

const (
	// IsolationLabelKey is label key for pods shall be isolated because of having vulnerability
	IsolationLabelKey = "tensorsec-isolation"
	// NamespaceLabelKey is label key attached to namespace
	NamespaceLabelKey = "tensorsec-namespace"
	// SegmentLabelKey is label key attached to pod to identify segment this pod is in
	SegmentLabelKey = "tensorsec-segment"
	// ResourceLabelKey is label key attached to pod to identify resource for per-resource policies
	ResourceLabelKey = "tensorsec-resource"
	// SegmentInvalidName is label value for 'SegmentLabelKey' when due to internal errors a proper
	// segment name couldn't not be attached
	SegmentInvalidName = "InvalidSegment"

	MutationDefaultConfigName = "microseg"
)
