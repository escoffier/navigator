package association

import (
	"container/list"
	"context"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ProcessTreeAssociation struct {
	tree      *processTree
	sid       uint64
	aggr      *ProcessTreeAggregator
	targetLoc TargetLocation
}

func (pte *ProcessTreeAssociation) GetID() uint64 {
	return pte.sid
}
func (pte *ProcessTreeAssociation) GetEvents() []OriginEvent {
	events := make([]OriginEvent, 0, pte.tree.eventsNum)
	pte.tree.bfs(func(node *processNode, level int) {
		for _, e := range node.events {
			events = append(events, e)
		}
	})
	return events
}
func (pte *ProcessTreeAssociation) GetAssociatedLinks() []Link {
	links := make([]Link, 0, pte.tree.nodesNum-1)
	pte.tree.bfs(func(node *processNode, level int) {
		if len(node.parentID) > 0 {
			links = append(links, Link{
				SrcAggrKey:  node.parentID,
				SrcLoc:      pte.targetLoc,
				DestAggrKey: node.id,
				DestLoc:     pte.targetLoc,
			})
		}
	})
	return links
}

func (pte *ProcessTreeAssociation) SetID(id int64) {
	pte.sid = id
	if pte.aggr.isStopped() {
		return
	}
	pte.aggr.setIDChan <- *pte
}

func getAggID(r *PodContainerEvent) (string, bool) {
	pid, ok := r.GetPid()
	if !ok || len(pid) == 0 {
		return "", false
	}
	pname, ok := r.GetPName()
	if !ok || len(pname) == 0 {
		return "", false
	}
	bui := strings.Builder{}
	bui.WriteString(pid)
	bui.WriteByte('-')
	bui.WriteString(pname)
	return bui.String(), true
}

func getParentAggID(r *PodContainerEvent) (string, bool) {
	ppid, ok := r.GetParentPid()
	if !ok || len(ppid) == 0 {
		return "", false
	}
	ppname, ok := r.GetParentPName()
	if !ok || len(ppname) == 0 {
		return "", false
	}
	bui := strings.Builder{}
	bui.WriteString(ppid)
	bui.WriteByte('-')
	bui.WriteString(ppname)
	return bui.String(), true
}

type processNode struct {
	id             string // pid:pname->ppid
	events         []*PodContainerEvent
	childrenIDs    map[string]struct{}
	parentID       string // parent process ID
	lastUpdateTime time.Time
	createTime     time.Time

	asID uint64
}

func (pn *processNode) setAssociationID(asID uint64) {
	for _, e := range pn.events {
		e.SetAssociationEventID(asID)
	}
	pn.asID = asID
}

func newProcessNode(id string, parentID string, updateTime time.Time) *processNode {
	return &processNode{
		id:             id,
		parentID:       parentID,
		childrenIDs:    make(map[string]struct{}, 2),
		lastUpdateTime: updateTime,
		createTime:     time.Now(),
	}
}
func (pn *processNode) addEvent(r *PodContainerEvent) {
	pn.events = append(pn.events, r)
	// save memory
	if r.Time().After(pn.lastUpdateTime) {
		pn.lastUpdateTime = r.Time()
	}
	if r.Time().Before(pn.createTime) {
		pn.createTime = r.Time()
	}
}

type processTree struct {
	lastUpdateTime time.Time
	eventsNum      int
	nodesNum       int
	root           *processNode
	aggr           *ProcessTreeAggregator
}

func newProcessTree(root *processNode, utime time.Time, aggr *ProcessTreeAggregator) *processTree {
	return &processTree{
		lastUpdateTime: utime,
		root:           root,
		aggr:           aggr,
	}
}

func (pt *processTree) setAssociationID(sid uint64) {
	pt.bfs(func(node *processNode, level int) {
		node.setAssociationID(sid)
	})
}

func (pt *processTree) bfs(visitNodeFunc func(node *processNode, level int)) {
	type tnode struct {
		node  *processNode
		level int
	}

	queue := list.New()
	queue.PushBack(tnode{pt.root, 0})

	for queue.Len() > 0 {
		currElem := queue.Front()
		currNode := currElem.Value.(tnode)

		visitNodeFunc(currNode.node, currNode.level)

		for childID := range currNode.node.childrenIDs {
			child, ok := pt.aggr.getNode(childID)
			if !ok {
				logging.GetLogger().Warn().Msgf("Error cannot find child %s for node %+v", childID, currNode)
			} else {
				queue.PushBack(tnode{child, currNode.level + 1})
			}
		}
	}
}

func (pt *processTree) stats() {
	pt.eventsNum = 0
	pt.nodesNum = 0

	pt.bfs(func(node *processNode, level int) {
		pt.eventsNum += len(node.events)
		pt.nodesNum++
	})
}

type ProcessTreeAggregator struct {
	config    AssociationConfiguration
	nodes     map[string]*processNode
	targetLoc TargetLocation

	updatedAt time.Time

	input     chan *PodContainerEvent
	output    chan AssociationEvent
	setIDChan chan ProcessTreeAssociation
	stopChan  chan struct{}
	stopped   uint32
}

func (ta *ProcessTreeAggregator) AssociationKind() string {
	return "process_tree"
}
func (ta *ProcessTreeAggregator) isStopped() bool {
	return atomic.LoadUint32(&ta.stopped) == 1
}
func (ta *ProcessTreeAggregator) setStopped() {
	atomic.StoreUint32(&ta.stopped, 1)
}

func NewProcessTreeAggregator(bconf AssociationConfiguration, targetLoc TargetLocation, output chan AssociationEvent) *ProcessTreeAggregator {
	a := &ProcessTreeAggregator{
		config:    bconf,
		nodes:     make(map[string]*processNode, 50),
		input:     make(chan *PodContainerEvent, 100),
		output:    output,
		setIDChan: make(chan ProcessTreeAssociation, 50),
		stopChan:  make(chan struct{}),
	}
	a.asyncLoop()
	return a
}

// RequireStop : It will be blocking till aggregator begins to do stop.
func (ta *ProcessTreeAggregator) RequireStop() {
	ta.stopChan <- struct{}{}
}

func (ta *ProcessTreeAggregator) AddEvent(ctx context.Context, event *PodContainerEvent) error {
	if ta.isStopped() {
		return ErrIsStopped
	}
	_, setted := ctx.Deadline()
	if !setted {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
	}
	select {
	case ta.input <- event:
	case <-ctx.Done():
		return ErrTimeout
	}
	return nil
}

func (ta *ProcessTreeAggregator) doStop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when stopping aggr: %v. stack: %s", r, debug.Stack())
		}
	}()

	ta.setStopped()
	// no more inputs
	close(ta.input)
	// clear buffer
	for stop := false; !stop; {
		select {
		case r, more := <-ta.input:
			if !more {
				stop = true
				break
			}
			ta.addEvent(r)
		default:
			stop = true
			break
		}
	}

	trees := ta.treeBuilding()
	ta.treeReviews(trees, time.Now())

	close(ta.setIDChan)
}
func (ta *ProcessTreeAggregator) asyncLoop() {
	go func() {
		ticker := time.NewTicker(ta.config.BuildInterval)
		defer ticker.Stop()

		for {
			select {
			case now := <-ticker.C:
				trees := ta.treeBuilding()
				ta.treeReviews(trees, now)
			case r := <-ta.input:
				ta.addEvent(r)
			case setSid := <-ta.setIDChan:
				setSid.tree.setAssociationID(setSid.sid)
			case <-ta.stopChan:
				ta.doStop()
				return
			}
		}
	}()

}

func (ta *ProcessTreeAggregator) getNode(id string) (*processNode, bool) {
	node, exist := ta.nodes[id]
	return node, exist
}

func (ta *ProcessTreeAggregator) cleanTree(t *processTree) {
	t.bfs(func(node *processNode, level int) {
		delete(ta.nodes, node.id)
	})
}

func (ta *ProcessTreeAggregator) outputs(tree *processTree) error {
	op := ProcessTreeAssociation{
		tree:      tree,
		aggr:      ta,
		targetLoc: ta.targetLoc,
	}
	select {
	case ta.output <- &op:
		return nil
	default:
		logging.GetLogger().Warn().Msgf("tree output timeout: tree: %+v", tree)
		return ErrTimeout
	}
}
func (ta *ProcessTreeAggregator) treeReviews(trees []*processTree, now time.Time) error {
	for _, tree := range trees {
		if now.Sub(tree.lastUpdateTime) >= ta.config.SubmitLatency {
			if tree.eventsNum == 1 {
				// ignore single events with few relations
				ta.cleanTree(tree)
				continue
			} else {
				ta.outputs(tree)
				ta.cleanTree(tree)
			}
		} else {
			if tree.eventsNum > 0 {
				ta.outputs(tree)
			}
		}
	}
	return nil
}

func (ta *ProcessTreeAggregator) treeBuilding() []*processTree {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v when building trees: %+v. stack: %s", r, r, debug.Stack())
		}
	}()
	trees := make(map[string]*processTree, len(ta.nodes))
	for _, node := range ta.nodes {
		root := node
		var latest time.Time
		for root != nil {
			if root.lastUpdateTime.After(latest) {
				latest = root.lastUpdateTime
			}
			if len(root.parentID) > 0 {
				parent, exist := ta.getNode(root.parentID)
				if !exist {
					break
				}
				parent.childrenIDs[root.id] = struct{}{}
				root = parent
			} else {
				break
			}
		}
		tree, exist := trees[root.id]
		if exist {
			if latest.After(tree.lastUpdateTime) {
				tree.lastUpdateTime = latest
			}
		} else {
			tree = newProcessTree(root, latest, ta)
			trees[root.id] = tree
		}
	}

	treesList := make([]*processTree, 0, len(trees))
	for _, tree := range trees {
		tree.stats()
		treesList = append(treesList, tree)
	}

	return treesList
}

func (ta *ProcessTreeAggregator) addEvent(r *PodContainerEvent) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v when adding event: %+v. stack: %s", r, r, debug.Stack())
		}
	}()

	aggID, ok := getAggID(r)
	if !ok {
		return ErrMissingSignificantKey
	}
	parentAggID, _ := getParentAggID(r)

	node, exist := ta.getNode(aggID)
	if !exist {
		node = newProcessNode(aggID, parentAggID, r.Time())
		ta.nodes[aggID] = node
	} else {
		if parentAggID != "" && node.parentID != parentAggID {
			logging.GetLogger().Warn().Msgf("[inconsistency] parent process ID doesn't match: %s != %s. data: %+v", parentAggID, node.parentID, r)
		}
	}
	node.addEvent(r)
	r.SetAggregationKey(aggID)

	if parentAggID != "" {
		parNode, pexist := ta.getNode(parentAggID)
		if !pexist {
			parNode = newProcessNode(parentAggID, "", r.Time())
			ta.nodes[parentAggID] = parNode
		}
		node.parentID = parentAggID
		if node.asID == 0 && parNode.asID > 0 {
			node.asID = parNode.asID
		}
	}

	etime := r.Time()
	if etime.After(ta.updatedAt) {
		ta.updatedAt = etime
	}

	return nil
}
