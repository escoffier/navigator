package association

import (
	"container/list"
	"context"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

type ProcessTreeAssociation struct {
	tree    *processTree
	agEvtID uint64
	aggr    *ProcessTreeAggregator
	events  []PodContainerEvent
	links   []Link
}

func newProcessTreeAssociation(evtID uint64, tree *processTree, aggr *ProcessTreeAggregator) *ProcessTreeAssociation {
	pte := ProcessTreeAssociation{
		agEvtID: evtID,
		tree:    tree,
		aggr:    aggr,
	}
	pte.generateData()
	return &pte
}
func (pte *ProcessTreeAssociation) GetEventsNum() int {
	return pte.tree.eventsNum
}
func (pte *ProcessTreeAssociation) GetNodesNum() int {
	return pte.tree.nodesNum
}
func (pte *ProcessTreeAssociation) GetID() uint64 {
	return pte.agEvtID
}

func (pte *ProcessTreeAssociation) generateData() {
	pte.events = make([]PodContainerEvent, 0, pte.tree.eventsNum)
	pte.links = make([]Link, 0, pte.tree.nodesNum-1)
	pte.tree.bfs(func(node *processNode, level int) {
		pte.events = append(pte.events, node.events...)
		pte.events = append(pte.events, node.historicalEvents...)

		if len(node.parentID) > 0 {
			pte.links = append(pte.links, Link{
				SrcAggrKey:  node.parentID,
				SrcLoc:      pte.aggr.targetLoc,
				DestAggrKey: node.id,
				DestLoc:     pte.aggr.targetLoc,
			})
		}
	})
}

func (pte *ProcessTreeAssociation) GetEvents() []PodContainerEvent {
	return pte.events
}
func (pte *ProcessTreeAssociation) GetAssociatedLinks() []Link {

	return pte.links
}

func (pte *ProcessTreeAssociation) PostActionSetting(evtID uint64, submitOK bool) {
	if submitOK && evtID > 0 {
		pte.agEvtID = evtID
	}
	if pte.aggr.isStopped() {
		return
	}
	pte.aggr.postActonChan <- postAction{
		agEvent:    pte,
		submitDone: true,
		submitOK:   submitOK,
	}
}

func (pte *ProcessTreeAssociation) SetID(id uint64) {
	if id == 0 {
		return
	}
	if id > 0 {
		pte.agEvtID = id
	}
	if pte.aggr.isStopped() {
		return
	}
	pte.aggr.postActonChan <- postAction{
		agEvent:    pte,
		submitDone: false,
	}
}

func getAggID(pid, pname string) string {
	bui := strings.Builder{}
	bui.WriteString(pid)
	bui.WriteByte('|')
	bui.WriteString(pname)
	return bui.String()
}

type processNode struct {
	id               string // pid:pname->ppid
	events           []PodContainerEvent
	historicalEvents []PodContainerEvent // stores the events submmited in the last turn
	childrenIDs      map[string]struct{}
	parentID         string // parent process ID
	historicalEvtCnt int
	lastUpdateTime   time.Time

	updateTxid uint64
	agEvtID    uint64
}

func (pn *processNode) setAssociationID(evtID uint64) {
	pn.agEvtID = evtID
}

func newProcessNode(id string, parentID string, updateTime time.Time) *processNode {
	return &processNode{
		id:             id,
		parentID:       parentID,
		childrenIDs:    make(map[string]struct{}, 2),
		lastUpdateTime: updateTime,
	}
}
func (pn *processNode) addEvent(r PodContainerEvent, txid uint64) {
	for _, e := range pn.events {
		if e.OriginID == r.OriginID {
			return
		}
	}

	pn.events = append(pn.events, r)

	if r.Time().After(pn.lastUpdateTime) {
		pn.lastUpdateTime = r.Time()
	}
	pn.updateTxid = txid
}

type processTree struct {
	lastUpdateTime time.Time
	eventsNum      int
	nodesNum       int
	root           *processNode
	aggr           *ProcessTreeAggregator
	txid           uint64
}

func newProcessTree(root *processNode, utime time.Time, aggr *ProcessTreeAggregator, txid uint64) *processTree {
	return &processTree{
		lastUpdateTime: utime,
		root:           root,
		aggr:           aggr,
		txid:           txid,
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
		queue.Remove(currElem)
		currNode := currElem.Value.(tnode)

		visitNodeFunc(currNode.node, currNode.level)

		for childID := range currNode.node.childrenIDs {
			child, ok := pt.aggr.getNode(childID)
			if ok {
				queue.PushBack(tnode{child, currNode.level + 1})
			}
		}
	}
}

func (pt *processTree) stats() {
	pt.eventsNum = 0
	pt.nodesNum = 0

	pt.bfs(func(node *processNode, level int) {
		pt.eventsNum += len(node.events) + node.historicalEvtCnt
		pt.nodesNum++
	})
}

type postAction struct {
	agEvent    *ProcessTreeAssociation
	submitDone bool
	submitOK   bool
}
type ProcessTreeAggregator struct {
	config Configuration

	nodes     map[string]*processNode
	targetLoc TargetLocation
	updatedAt time.Time
	txid      uint64 // incr txid after one building of trees

	input         chan PodContainerEvent
	output        chan Event
	postActonChan chan postAction
	stopChan      chan struct{}
	stopped       uint32
	treeDelBuffer map[*processTree]struct{}
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

func NewProcessTreeAggregator(bconf Configuration, targetLoc TargetLocation, output chan Event) *ProcessTreeAggregator {
	a := &ProcessTreeAggregator{
		config:        bconf,
		targetLoc:     targetLoc,
		nodes:         make(map[string]*processNode, 50),
		input:         make(chan PodContainerEvent, 100),
		output:        output,
		postActonChan: make(chan postAction, 50),
		stopChan:      make(chan struct{}),
		treeDelBuffer: make(map[*processTree]struct{}, 5),
	}
	a.asyncLoop()
	return a
}

// RequireStop : It will be blocking till aggregator begins to do stop.
func (ta *ProcessTreeAggregator) RequireStop() {
	logging.Get().Info().Msgf("aggr %s is required to stop.", ta.targetLoc.String())
	ta.stopChan <- struct{}{}
}

func (ta *ProcessTreeAggregator) AddEvent(ctx context.Context, event PodContainerEvent) error {
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

func (ta *ProcessTreeAggregator) doCleanBufferOfTree(tree *processTree) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	if tree.txid == ta.txid {
		return
	}
	tree.bfs(func(node *processNode, level int) {
		node.historicalEvents = nil
	})
}
func (ta *ProcessTreeAggregator) doStop() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic when stopping aggr: %v. stack: %s", r, debug.Stack())
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
			if err := ta.addEvent(r); err != nil {
				logging.Get().Err(err).Msgf("add event err. evt: %+v", r)
			}
		default:
			stop = true
			break
		}
	}

	trees := ta.treeBuilding()
	if err := ta.treeReviews(trees, time.Now()); err != nil {
		logging.Get().Err(err).Msg("tree reviews error")
	}

	close(ta.postActonChan)

	logging.Get().Info().Msgf("aggr %s has stopped", ta.targetLoc.String())
}

func (ta *ProcessTreeAggregator) postAction(action postAction) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	action.agEvent.tree.setAssociationID(action.agEvent.agEvtID)
	if action.submitDone && action.submitOK {
		if _, toDel := ta.treeDelBuffer[action.agEvent.tree]; toDel {
			ta.cleanTree(action.agEvent.tree, true)
			delete(ta.treeDelBuffer, action.agEvent.tree)
		} else {
			ta.doCleanBufferOfTree(action.agEvent.tree)
		}
	}

}

func (ta *ProcessTreeAggregator) periodicallyBuild(now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	ta.treeDelBuffer = make(map[*processTree]struct{}, len(ta.treeDelBuffer)+5)

	trees := ta.treeBuilding()
	if err := ta.treeReviews(trees, now); err != nil {
		logging.Get().Err(err).Msg("tree reviews error")
	}

}
func (ta *ProcessTreeAggregator) asyncLoop() {
	go func() {
		ticker := time.NewTicker(ta.config.BuildInterval)
		defer ticker.Stop()

		for {
			select {
			case action := <-ta.postActonChan:
				ta.postAction(action)
			case r := <-ta.input:
				if err := ta.addEvent(r); err != nil {
					logging.Get().Err(err).Msgf("add event err. evt: %+v", r)
				}
			case now := <-ticker.C:
				// when time to build, first consume all buffers of postActions
				toStop := false
				for !toStop {
					select {
					case action := <-ta.postActonChan:
						ta.postAction(action)
					default:
						toStop = true
					}
				}

				ta.periodicallyBuild(now)
				// increase the txid for the next round of building
				ta.txid++

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

func (ta *ProcessTreeAggregator) cleanTree(t *processTree, cleanBuffer bool) {
	logging.Get().Info().Msgf("[%d] tree(%s-%s) is cleaned. try to cleanBuffer: %v", t.txid, t.root.id, ta.targetLoc.String(), cleanBuffer)
	t.bfs(func(node *processNode, level int) {
		if node.updateTxid < ta.txid {
			delete(ta.nodes, node.id)
		} else if cleanBuffer {
			node.agEvtID = 0
			node.historicalEvents = nil
		}
	})
}

func (ta *ProcessTreeAggregator) evtIDNegotiation(tree *processTree) uint64 {
	idCount := make(map[uint64]int, 2)
	tree.bfs(func(node *processNode, level int) {
		if node.agEvtID > 0 {
			cnt := idCount[node.agEvtID]
			cnt++
			idCount[node.agEvtID] = cnt
		}
	})
	maxCntSid := uint64(0)
	maxCnt := 0
	for sid, cnt := range idCount {
		if cnt > maxCnt {
			maxCntSid = sid
		}
	}
	if maxCntSid > 0 {
		if len(idCount) > 0 {
			logging.Get().Warn().Msgf("consistent to one sid: %d from: %v", maxCntSid, idCount)
		}

		tree.bfs(func(node *processNode, level int) {
			node.setAssociationID(maxCntSid)
		})
	}
	return maxCntSid
}

func (ta *ProcessTreeAggregator) outputs(tree *processTree) error {
	if tree.root == nil {
		return nil
	}
	sid := ta.evtIDNegotiation(tree)

	op := newProcessTreeAssociation(sid, tree, ta)

	logging.Get().Info().Msgf("Output a agEvent: %+v. evtID: %d", *tree, op.agEvtID)

	// move the submitted events to historical for the object of cleanning out the previous buffers
	tree.bfs(func(node *processNode, level int) {
		node.historicalEvtCnt += len(node.events)
		node.historicalEvents = node.events
		node.events = make([]PodContainerEvent, 0, len(node.historicalEvents))
	})

	select {
	case ta.output <- op:
		return nil
	default:
		logging.Get().Warn().Msgf("tree output timeout: tree: %+v", tree)
		return ErrTimeout
	}
}
func (ta *ProcessTreeAggregator) scheduleDeleteTree(tree *processTree) {
	ta.treeDelBuffer[tree] = struct{}{}
}
func (ta *ProcessTreeAggregator) treeReviews(trees []*processTree, now time.Time) error {
	for _, tree := range trees {
		// for the timeout historical nodes, recover them.
		tree.bfs(func(node *processNode, level int) {
			if len(node.historicalEvents) > 0 {
				logging.Get().Info().Msgf("node %s in %s histEvents not cleaned", node.id, ta.targetLoc.String())

				node.events = append(node.events, node.historicalEvents...)
				node.historicalEvents = nil
				node.historicalEvtCnt -= len(node.historicalEvents)
			}
		})

		if now.Sub(tree.lastUpdateTime) >= ta.config.WindowDivisionLatency {
			if tree.eventsNum == 1 {
				// ignore single events with few relations
				ta.cleanTree(tree, false)
			} else {
				if err := ta.outputs(tree); err != nil {
					logging.Get().Err(err).Msg("output error")
				} else {
					ta.scheduleDeleteTree(tree)
				}
			}
		} else {
			if tree.eventsNum > 1 {
				if err := ta.outputs(tree); err != nil {
					logging.Get().Err(err).Msg("output error")
				}
			}
		}
	}
	return nil
}

func (ta *ProcessTreeAggregator) treeBuilding() (treesList []*processTree) {
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
					logging.Get().Warn().Msgf("cannot find parent node of ID: %s for node: %s", root.parentID, root.id)
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
			tree = newProcessTree(root, latest, ta, ta.txid)
			trees[root.id] = tree
		}
	}

	treesList = make([]*processTree, 0, len(trees))
	for _, tree := range trees {
		tree.stats()
		treesList = append(treesList, tree)
	}

	return treesList
}

func (ta *ProcessTreeAggregator) addEvent(r PodContainerEvent) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v when adding event: %+v. stack: %s", r, r, debug.Stack())
		}
	}()

	pid, exist := r.Pid()
	if !exist {
		return ErrMissingSignificantKey
	}
	pname, exist := r.ProcessName()
	if !exist {
		return ErrMissingSignificantKey
	}
	aggID := getAggID(pid, pname)
	r.SetAggregationKey(aggID)

	var parentAggID string
	ppid, exist := r.ParentPid()
	if exist {
		ppname, exist := r.ParentProcessName()
		if exist {
			parentAggID = getAggID(ppid, ppname)
		}
	}

	node, exist := ta.getNode(aggID)
	if !exist {
		node = newProcessNode(aggID, parentAggID, r.Time())
		ta.nodes[aggID] = node
	} else if parentAggID != "" && node.parentID != parentAggID {
		logging.Get().Warn().Msgf("[inconsistency] parent process ID doesn't match: %s != %s. data: %+v", parentAggID, node.parentID, r)
	}
	node.addEvent(r, ta.txid)

	if parentAggID != "" {
		parNode, pexist := ta.getNode(parentAggID)
		if !pexist {
			parNode = newProcessNode(parentAggID, "", r.Time())
			ta.nodes[parentAggID] = parNode
		} else if parNode.agEvtID > 0 {
			if node.agEvtID == 0 {
				node.setAssociationID(parNode.agEvtID)
			} else if node.agEvtID != parNode.agEvtID {
				logging.Get().Warn().Msg("[inconsistency] node asID %d != parent node asID %d.")
			}
		}
		node.parentID = parentAggID
		if parNode.agEvtID == 0 && node.agEvtID > 0 {
			parNode.setAssociationID(node.agEvtID)
		}
	}

	etime := r.Time()
	if etime.After(ta.updatedAt) {
		ta.updatedAt = etime
	}

	return nil
}
