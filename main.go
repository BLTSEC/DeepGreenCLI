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

func printEvents(re *regexp.Regexp) {
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

	for _, winLog := range logs {
		file, err := os.Open(winLog)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			reMatch := re.FindStringSubmatch(scanner.Text())
			if reMatch == nil {
				continue
			}

			eventID := reMatch[1]

			if strings.Contains(eventID, "4663") {
				match4663 := re.FindStringSubmatch(scanner.Text())
				server := strings.Replace(match4663[2], "Success Audit\t", "", -1)
				user := strings.Replace(match4663[3], "Account Name: ", "", -1)
				object := strings.Replace(match4663[4], "Object Name: ", "", -1)
				process := strings.Replace(match4663[6], "Process Name: ", "", -1)
				preUniqResult = append(preUniqResult, eventID+", "+server+", "+user+", "+process+", "+object)
				continue
			}

			if strings.Contains(eventID, "4722") || strings.Contains(eventID, "4725") {
				match4722m4725 := re.FindStringSubmatch(scanner.Text())
				user := strings.Replace(match4722m4725[3], "ACULOCAL\\", "", -1)
				admin := match4722m4725[6]
				if strings.Contains(user, admin) {
					continue
				}
				preUniqResult = append(preUniqResult, eventID+", "+user+", "+admin)
				continue
			}

			if strings.Contains(eventID, "4720") {
				matchre4720 := re.FindStringSubmatch(scanner.Text())
				atrribs := matchre4720[3]
				preUniqResult = append(preUniqResult, eventID+", "+atrribs)
				continue
			}

			if strings.Contains(eventID, "4688") {
				matchre4688 := re.FindStringSubmatch(scanner.Text())
				server1 := matchre4688[3]
				user1 := matchre4688[4]
				user2 := matchre4688[5]
				server2 := matchre4688[6]
				process := matchre4688[7]
				tokenName := matchre4688[8]
				tokenLevel := matchre4688[9]
				creatorProcess := matchre4688[10]
				if strings.Contains(creatorProcess, "0x") {
					preUniqResult = append(preUniqResult, eventID+", "+server1+", "+user1+", "+user2+", "+server2+", "+process+", "+tokenName+" "+tokenLevel)
				} else {
					preUniqResult = append(preUniqResult, eventID+", "+server1+", "+user1+", "+user2+", "+server2+", "+process+", "+creatorProcess)
				}
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

	re4663 := regexp.MustCompile(`(?m)(?P<eventid>4663	Microsoft-Windows-Security-Auditing.*?).+(?P<server>Success Audit\s.*?\S+).+(?P<subject>Account Name:\s.*?\S+).+(?P<object>Object Name:\s.*\S).+(\sHandle).+(?P<process>Process Name:\s.*\S).+(\sAccess Request)`)
	re4722re4725 := regexp.MustCompile(`(?m)(4722|4725).*(	Microsoft-Windows-Security-Auditing.*?\t)(.*\S).*(N/A).*(Account Name:  )(.*)(Account Domain:  ACULOCAL   Logon ID:)`)
	re4720 := regexp.MustCompile(`(?m)(?P<eventid>4720)(\tMicrosoft-Windows-Security-Auditing.*?)Account Name:.*?(Account Name:.*)(Additional Information:.*)`)
	re4688 := regexp.MustCompile(`(?m)(?P<one>4688)(\tMicrosoft-Windows-Security-Auditing.*?)Audit\s(?P<three>[^ \s]*).*?Account Name:\s\s(?P<four>[^ ]*)\s{3}Account Domain:\s{2}ACULOCAL.*Account Name:\s{2}(?P<five>[^ ]*)\s{3}Account Domain:\s{2}(?P<six>[^ ]*).*New Process Name:\s(?P<seven>[^ ]*).*?Token Elevation Type:\s(?P<eight>[^ ]*).(?P<nine>[^ ]*).*Creator Process\s\w*:\s(?P<ten>[^ ]*)`)

	printEvents(re4663)
	printEvents(re4722re4725)
	printEvents(re4720)
	printEvents(re4688)

	exec.Command("/bin/bash", "-c", "cat /home/blt15b/win-events-results | mail -s 'Windows Events' blt15b").Output()
}
