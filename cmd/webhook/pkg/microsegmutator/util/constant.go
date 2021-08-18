package util

const (
	// SegmentLabelKey is label key attached to pod to identifiy segment this pod is in
	SegmentLabelKey = "tensorsec-segment"
	// ResourceLabelKey is label key attached to pod to identify resource for per-resource policies
	ResourceLabelKey = "tensorsec-resource"
	// SegmentInvalidName is label value for 'SegmentLabelKey' when due to internal errors a proper
	// segment name couldn't not be attached
	SegmentInvalidName = "InvalidSegment"

	MutationDefaultConfigName = "microseg"
)
