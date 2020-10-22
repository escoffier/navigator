package producer

// func TestProducer(t *testing.T) {
// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, os.Interrupt, os.Kill)

// 	syscallName := "open"
// 	p := NewSyscallProducer(&syscallName)
// 	p.Init()
// 	go p.Start()
// 	<-sigChan
// 	log.Error("sigInt catched.")
// 	p.Stop()
// 	log.Error("sigQuit catched.")
// }
