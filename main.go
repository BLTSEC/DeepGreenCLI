package main

import (

	//"io/ioutil"
	"time"
	"strings"
	"path/filepath"
	"os"
	"log"
	"bufio"
	"regexp"
	"fmt"
)

func printEvents(re *regexp.Regexp) {
	captures := make(map[string]string)

	todayParent := strings.Replace(time.Now().Format("01-2006"), "-", "", -1)
	todayChild := strings.Replace(time.Now().Format("01-02-2006"), "-", "", -1)
	logs, _ := filepath.Glob("/log/" + todayParent + "/" + todayChild + "/" + "snare*")

	for _, winLog := range logs {
		file, err := os.Open(winLog)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			match := re.FindStringSubmatch(scanner.Text())
			if match == nil {
				continue
			}

			for i, name := range re.SubexpNames() {
				if i == 0 {
					continue
				}

				captures[name] = match[i]

				eventID := captures["eventid"]

				if strings.Contains(eventID, "4663") {

					server := strings.Replace(captures["server"], "Success Audit", "", -1)
					user := strings.Replace(captures["subject"], "Account Name:", "", -1)
					object := strings.Replace(captures["object"], "Object Name: ", "", -1)
					process := strings.Replace(captures["process"], "Process Name: ", "", -1)
					fmt.Println(match)
					fmt.Println(server, user, object, process)
				}

				fmt.Println()
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

}

func main() {

	re4663 := regexp.MustCompile(`(?m)(?P<eventid>4663	Microsoft-Windows-Security-Auditing.*?).+(?P<server>Success Audit\s.*?\S+).+(?P<subject>Account Name:\s.*?\S+).+(?P<object>Object Name:\s.*?\S+).+(?P<process>Process Name:\s.*?\S+)`)
	printEvents(re4663)

}
