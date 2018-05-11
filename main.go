package main

import (
	"time"
	"strings"
	"path/filepath"
	"os"
	"log"
	"bufio"
	"regexp"
	"os/exec"
)

func removeDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	// Return the new slice.
	return result
}

func printEvents() {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile("/home/blt15b/win-events-results", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	preUniqResult := []string{}

	todayParent := strings.Replace(time.Now().Format("01-2006"), "-", "", -1)
	todayChild := strings.Replace(time.Now().Format("01-02-2006"), "-", "", -1)
	logs, _ := filepath.Glob("/log/" + todayParent + "/" + todayChild + "/" + "snare*")

	ogRE := regexp.MustCompile(`(?m)([0-9]{4}\t)(4722|4725|4663)(\tMicrosoft-Windows-Security-Auditing)`)
	re4663 := regexp.MustCompile(`(?m)(?P<eventid>4663	Microsoft-Windows-Security-Auditing.*?).+(?P<server>Success Audit\s.*?\S+).+(?P<subject>Account Name:\s.*?\S+).+(?P<object>Object Name:\s.*\S).+(\sHandle).+(?P<process>Process Name:\s.*\S).+(\sAccess Request)`)
	re4722re4725 := regexp.MustCompile(`(?m)(4722|4725).*(	Microsoft-Windows-Security-Auditing.*?\t)(.*\S).*(N/A).*(Account Name:  )(.*)(Account Domain:  ACULOCAL   Logon ID:)`)

	for _, winLog := range logs {
		file, err := os.Open(winLog)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			ogMatch := ogRE.FindStringSubmatch(scanner.Text())
			if ogMatch == nil {
				continue
			}

			eventID := ogMatch[2]

			if strings.Contains(eventID, "4663") {
				match4663 := re4663.FindStringSubmatch(scanner.Text())
				server := strings.Replace(match4663[2], "Success Audit\t", "", -1)
				user := strings.Replace(match4663[3], "Account Name: ", "", -1)
				object := strings.Replace(match4663[4], "Object Name: ", "", -1)
				process := strings.Replace(match4663[6], "Process Name: ", "", -1)

				preUniqResult = append(preUniqResult, eventID + "," + server + "," + user + "," + process + "," + object)
			}

			if strings.Contains(eventID, "4722") || strings.Contains(eventID, "4725") {
				match4722m4725 := re4722re4725.FindStringSubmatch(scanner.Text())
				user := strings.Replace(match4722m4725[3], "ACULOCAL\\", "", -1)
				admin := match4722m4725[6]

				preUniqResult = append(preUniqResult, eventID + "," + user + "," + admin)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	result := removeDuplicates(preUniqResult)
	for _, event := range result {
		f.Write([]byte(event + "\n"))
	}

	f.Write([]byte("\n"))
}

func main() {

	os.Remove("/home/blt15b/win-events-results")

	printEvents()

	exec.Command("/bin/bash", "-c", "cat /home/blt15b/win-events-results | mail -s 'Windows Events' blt15b").Output()
}
