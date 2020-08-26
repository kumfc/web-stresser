package main

import (
	"bytes"
	"fmt"
	"github.com/google/shlex"
	jsoniter "github.com/json-iterator/go"
	"github.com/julienschmidt/httprouter"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type M map[string]interface{}

type Attack struct {
	Cmd string `json:"cmd"`
	Duration time.Duration `json:"duration"`
	BandwidthKbps int64 `json:"bandwidth"`
}

var attack *Attack
var attackProcess *exec.Cmd
var in string

type Communication struct {
	req chan bool
	resp chan bool
	run chan bool
	err string
}

var talking = Communication{
	req:  make(chan bool),
	resp: make(chan bool),
	run: make(chan bool),
	err: "",
}

func MustB(a []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return a
}

// helper to kill attack
func kill() error {
	pgid, err := syscall.Getpgid(attackProcess.Process.Pid)
	if err != nil {
		fmt.Println("Can't get process group, gonna try killing normally," +
			"this is bound to fail if process has children...")
		err = attackProcess.Process.Kill()
	} else {
		err = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	return err
}

// helper for rate limiting
func limit() {
	stoplimit()
	exec.Command("sudo", "wondershaper", "-a", in, "-u", strconv.Itoa(int(attack.BandwidthKbps))).Run()
}

func stoplimit() {
	exec.Command("sudo", "wondershaper", "-a", in, "-c").Run()
}

// constantly wait for run queries and requests about process status
func Runner() {
	var done chan bool = nil
	for ;; {
		select {
		case <-talking.run:
			fmt.Printf("Starting new process: \"%s\"\n", attack.Cmd)
			if done != nil { talking.resp<- true }
			talking.err = ""
			tmp := make(chan bool)
			// channel is available only when a process is running
			done = make(chan bool)
			// try to start attack, if it fails then instantly say done
			go func() {
				// can't have invalid duration
				if attack.Duration < 0 || attack.Duration > 2419200 {
					talking.err = fmt.Sprintf(
						  "can't launch attack with negative duration or duration larger than a month",
						          )
					tmp<- false
					done<- false
					return
				}

				// can't limit higher than 1Gbps
				if attack.BandwidthKbps < 0 || attack.BandwidthKbps > 1024 * 1024 {
					talking.err = fmt.Sprintf(
						"can't launch attack with negative bandwidth or bandwith higher than 1Gbps",
					)
					tmp<- false
					done<- false
					return
				}

				attackProcess.Stdout = os.Stdout
				err := attackProcess.Start()
				// couldn't start process, let's report it
				if err != nil {
					talking.err = fmt.Sprintf("can't start process, error: %s", err)
					tmp<- false
					done<- false
					return
				}

				// everything is good, start waiters and limit
				tmp<- true
				limit()
				finished := make(chan bool)
				go func(){
					if err = attackProcess.Wait(); err != nil {
						talking.err = err.Error()
					}
					finished<- true
				}()

				select {
				// if program finished before timeout, simply stop the goroutine
				case <-finished:
					break
				// otherwise need to kill the process
				case <-time.After(time.Second * attack.Duration):
					fmt.Printf("Killing attack \"%s\" because of duration timeout\n", attack.Cmd)
					err := kill()
					<-finished
					talking.err = ""
					if err != nil {
						talking.err = err.Error()
					}
				}
				done<- true
			}()
			<-tmp
			select {
			// need to instantly close the attack/channels
			case d := <-done:
				talking.resp<- d
				attack, attackProcess = nil, nil
				done = nil
				stoplimit()
			default:
				talking.resp<- true
			}
		case rq := <-talking.req:
			// if we receive a 0 request, then kill the process and wait for goroutine to exit
			if !rq {
				fmt.Printf("Got a kill request, killing attack \"%s\"\n", attack.Cmd)
				if done == nil {
					talking.resp<- true
					break
				}
				err := kill()
				<-done
				// clear error, cause if we hadn't gotten an error by now,
				// we will only get a "signal: killed" error, and then set exit error
				talking.err = ""
				if err != nil {
					talking.err = err.Error()
				}
				talking.resp<- err == nil
				done = nil
				attack, attackProcess = nil, nil
			// otherwise just check if we are done (if no channel exists then we aren't running)
			} else {
				fmt.Println("Got a status check request")
				if done == nil {
					talking.resp<- true
					break
				}
				talking.resp<- false
			}
		case <-done:
			fmt.Println("Attack finished successfully")
			attack, attackProcess = nil, nil
			done = nil
		default:
		}
	}
}

func StartAttack(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if attack == nil {
		attack = new(Attack)
		bodybuf := bytes.NewBuffer([]byte{})
		_, err := bodybuf.ReadFrom(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(
				MustB(jsoniter.Marshal(
					M{"ok": false, "error": fmt.Sprintf("unable to read request body - %s", err)},
				)))
			w.Header().Set("Content-Type", "application/json")
			attack = nil
			return
		}
		err  = jsoniter.Unmarshal(bodybuf.Bytes(), attack)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(
				MustB(jsoniter.Marshal(
					M{"ok": false, "error": fmt.Sprintf("unable to parse received json - %s", err)},
				)))
			w.Header().Set("Content-Type", "application/json")
			attack = nil
			return
		}
		args, err := shlex.Split(attack.Cmd)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(
				MustB(jsoniter.Marshal(
					M{"ok": false, "error": fmt.Sprintf("invalid command received, can't parse - %s", err)},
				)))
			w.Header().Set("Content-Type", "application/json")
			attack = nil
			return
		}
		attackProcess = exec.Command(args[0], args[1:]...)
		// create a process with group, so that we can kill all the children
		attackProcess.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		talking.run<- true
		if res := <-talking.resp; res {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("{\"ok\": true}"))
			w.Header().Set("Content-Type", "application/json")
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(
				MustB(jsoniter.Marshal(
					M{"ok": false, "error": fmt.Sprintf("unable to start process, error: %s", talking.err)},
				)))
			w.Header().Set("Content-Type", "application/json")
			attack = nil
			return
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(
			[]byte("{\"ok\": false, \"error\": \"previous attack still running\"}"))
		w.Header().Set("Content-Type", "application/json")
		attack = nil
		return
	}
}

func CheckAttack(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	talking.req<- true
	select {
	case res := <-talking.resp:
		w.WriteHeader(http.StatusOK)
		if res {
			if talking.err != "" {
				w.Write(
					MustB(jsoniter.Marshal(
						M{"ok": true, "status":"failed", "error": fmt.Sprintf("process failed with error: %s", talking.err)},
					)))
			} else {
				w.Write([]byte("{\"ok\":true, \"status\":\"finished\"}"))
			}
		} else {
			w.Write([]byte("{\"ok\":true, \"status\":\"running\"}"))
		}
		w.Header().Set("Content-Type", "application/json")
	case <-time.After(time.Second):
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"ok\":false, \"error\":\"timed out, check the machine\"}"))
		w.Header().Set("Content-Type", "application/json")
		return
	}
}

func KillAttack(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	talking.req<- false
	resp := <-talking.resp
	w.WriteHeader(http.StatusInternalServerError)
	if resp {
		w.Write([]byte("{\"ok\":true}"))
	} else {
		w.Write(
			MustB(jsoniter.Marshal(
				M{"ok": false, "error": fmt.Sprintf("couldn't kill process, it must've already died: %s", talking.err)},
			)))
	}
	w.Header().Set("Content-Type", "application/json")
}

func Ping(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"pong\":\"pong\"}"))
	w.Header().Set("Content-Type", "application/json")
}

func PanicRecovery(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if rw.Header().Get("Content-Type") == "" {
					rw.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()

		handler.ServeHTTP(rw, rq)
	})
}

func main() {
	router := httprouter.New()
	router.POST("/startattack", StartAttack)
	router.POST("/killattack", KillAttack)
	router.GET("/checkattack", CheckAttack)
	router.GET("/ping", Ping)

	go Runner()

	interfaces, _ := net.Interfaces()
	for _, e := range interfaces {
		if !strings.Contains(e.Name, "lo") &&
		   !strings.Contains(e.Name, "vi") &&
		   !strings.Contains(e.Name, "wl") {
			in = e.Name
			break
		}
	}

	if in == "" {
		fmt.Println("Unable to get interface!")
		return
	}

	err := http.ListenAndServe("0.0.0.0:9009", PanicRecovery(router))
	fmt.Printf("Can't recover from panic in http server / Can't serve: %s\n", err)
}