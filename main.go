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
	"sync"
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

	var wg = sync.WaitGroup{}

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

		wg.Add(1)
		go func(winLog string) {
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

				// 4663: An attempt was made to access an object
				if strings.Contains(eventID, "4663") {
					eventID := strings.Replace(eventID, "	Microsoft-Windows-Security-Auditing", "", -1)
					server := strings.Replace(reMatch[2], "Success Audit\t", "", -1)
					user := strings.Replace(reMatch[3], "Account Name: ", "", -1)
					object := strings.Replace(reMatch[4], "Object Name: ", "", -1)
					process := strings.Replace(reMatch[6], "Process Name: ", "", -1)
					preUniqResult = append(preUniqResult, eventID+", "+server+", "+user+", "+process+", "+object)
					continue
				}

				// 4722: A user account was enabled
				// 4725: A user account was disabled
				if strings.Contains(eventID, "4722") || strings.Contains(eventID, "4725") {
					user := strings.Replace(strings.Replace(reMatch[3], "ACULOCAL\\", "", -1), " ", "", -1)
					admin := strings.Replace(reMatch[6], " ", "", -1)
					if user != admin {
						preUniqResult = append(preUniqResult, eventID+", "+user+", "+admin)
					}
					continue
				}

				// 4720: A user account was created
				if strings.Contains(eventID, "4720") {
					atrribs := reMatch[3]
					preUniqResult = append(preUniqResult, eventID+", "+atrribs)
					continue
				}

				//// 4688: A new process has been created BACKUP
				//if eventID == "4688" {
				//	server1 := reMatch[3]
				//	user1 := reMatch[4]
				//	user2 := reMatch[5]
				//	server2 := reMatch[6]
				//	process := reMatch[7]
				//	//tokenName := reMatch[8]
				//	//tokenLevel := reMatch[9]
				//	creatorProcess := reMatch[10]
				//	if strings.Contains(user1, "$") {
				//		continue
				//	}
				//	if strings.Contains(creatorProcess, "0x") {
				//		preUniqResult = append(preUniqResult, eventID+", "+server1+", "+user1+", "+user2+", "+server2+", "+process)
				//	} else {
				//		preUniqResult = append(preUniqResult, eventID+", "+server1+", "+user1+", "+user2+", "+server2+", "+process+", "+creatorProcess)
				//	}
				//	continue
				//}

				// 4688: A new process has been created
				if eventID == "4688" && !strings.EqualFold(reMatch[6], "0x3e7") && !strings.EqualFold(reMatch[6], "0x3e5") {
					preUniqResult = append(preUniqResult, eventID+", "+reMatch[2]+", "+reMatch[3]+", "+reMatch[4]+", "+reMatch[5]+", "+reMatch[6]+", "+reMatch[7]+", "+reMatch[8]+", "+reMatch[9]+", "+reMatch[10])
					continue
				}

				// 5140: A network share object was accessed
				if eventID == "5140" {
					user := reMatch[3]
					server := reMatch[4]
					user2 := reMatch[5]
					sourceIP := reMatch[6]
					sourcePort := reMatch[7]
					shareName := reMatch[8]
					preUniqResult = append(preUniqResult, eventID+", "+user+", "+server+", "+user2+", "+sourceIP+", "+sourcePort+", "+shareName)
					continue
				}

				// 7040: A new service has changed. Static system don't change details of services.
				if eventID == "7040" {
					system := reMatch[3]
					info := reMatch[4]
					preUniqResult = append(preUniqResult, eventID+", "+system+", "+info)
					continue
				}

				// 7045: A new service is installed. Static systems don't get new services except at patch time and new installs
				if eventID == "7045" {
					system := reMatch[3]
					serviceName := reMatch[4]
					serviceLocation := reMatch[5]
					serviceInfo := reMatch[6]
					preUniqResult = append(preUniqResult, eventID+", "+system+", "+serviceName+", "+serviceLocation+", "+serviceInfo)
					continue
				}

				// 4624: An account was successfully logged on
				if eventID == "4624" && reMatch[5] != "SYSTEM" && (reMatch[2] != "-" && reMatch[3] != "-" && !strings.Contains(reMatch[5], "$")) && reMatch[9] != "150.252.134.143"{
					systemAccountName := reMatch[2]
					systemDomain := reMatch[3]
					logonType := reMatch[4]
					userAccountName := reMatch[5]
					userDomain := reMatch[6]
					processName := reMatch[7]
					workstationName := reMatch[8]
					sourceIP := reMatch[9]
					//sourcePort := reMatch[10]
					logonProcess := reMatch[11]
					authPackage := reMatch[12]
					preUniqResult = append(preUniqResult, eventID+" :: "+logonType+", "+systemAccountName+", "+systemDomain+", "+userAccountName+", "+userDomain+", "+processName+", "+workstationName+", "+sourceIP+", "+logonProcess+", "+authPackage)
					continue
				}

				// 4648: A logon was attempted using explicit credentials
				if eventID == "4648" && reMatch[12] != "150.252.134.143" && (reMatch[4] != "SYSTEM" && reMatch[5] != "NT") && !strings.EqualFold(reMatch[6], "0x3e7") && !strings.EqualFold(reMatch[6], "0x3e5") && reMatch[7] != "SophosUpdateMgr" && !strings.Contains(reMatch[11], "SWJobEngineWorker2.exe") {
					preUniqResult = append(preUniqResult, eventID+", "+reMatch[2]+", "+reMatch[3]+", "+reMatch[4]+", "+reMatch[5]+", "+reMatch[6]+", "+reMatch[7]+", "+reMatch[8]+", "+reMatch[9]+", "+reMatch[10]+", "+reMatch[11]+", "+reMatch[12]+", "+reMatch[13])
					continue
				}

				// 4672: Special privileges assigned to new logon
				if eventID == "4672" {
					preUniqResult = append(preUniqResult, eventID+", "+reMatch[2]+", "+reMatch[3]+", "+reMatch[4]+", "+reMatch[5]+", "+reMatch[6])
				}
			}
			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}

			wg.Done()
		}(winLog)
	}

	wg.Wait()

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
	// BACKUP re4688 := regexp.MustCompile(`(?m)(?P<one>4688)(\tMicrosoft-Windows-Security-Auditing.*?)Audit\s(?P<three>[^ \s]*).*?Account Name:\s\s(?P<four>[^ ]*)\s{3}Account Domain:\s{2}ACULOCAL.*Account Name:\s{2}(?P<five>[^ ]*)\s{3}Account Domain:\s{2}(?P<six>.*).*\s{3}Logon ID:.*New Process Name:\s(?P<seven>.*).*?\s{3}Token Elevation Type:\s(?P<eight>[^ ]*).(?P<nine>[^ ]*).*Creator Process\s\w*:\s(?P<ten>.*).*\s{3}Process`)
	re4688 := regexp.MustCompile(`(?m)(4688)\t.*?g\s([^ ]*)\sN.*?t\s([^ ]*)\sP.*?e:\s{2}([^ ]*).*?n:\s{2}([^ ]*).*?D:\s{2}([^ ]*).*?e:\s{2}([^ ]*)\s{3}A.*?:\s{2}([^ ]*).*?D:\s{2}([^ ]*).*?e:\s(.*?)\s{3}`)
	re5140 := regexp.MustCompile(`(?m)(?P<eventid>5140)(\tMicrosoft-Windows-Security-Auditing.*?).(?P<twoUser>.*?)\tN/A\sSuccess\sAudit.(?P<threeServer>.*?)\s.*?Account\sName:\s(?P<fourUser>.*?)\s{3}Account.*Source\sAddress:\s(?P<fiveSource>.*?)\s{2}.Source\sPort:\s(?P<sixPort>.*?)\s{4}.Share.*Name:\s(?P<sevenShare>.*?)\s.*$`)
	//re7040 := regexp.MustCompile(`(?m)(?P<eventid>7040)(\tService Control Manager.*?)Information\s(?P<system>.*?)\s\w*\t\t(?P<info>.*)\s`)
	//re7045 := regexp.MustCompile(`(?m)(?P<eventid>7045)(\tService Control Manager.*?)Information\s(?P<system>.*?)\s\w*\t.*Service\sName:\s{2}(.*?)Service\sFile\sName:\s{2}(.*)Service\sType:\s{2}(.*)Service\sAccount`)
	re4624 := regexp.MustCompile(`(?m)(4624)\t.*?me:\s{2}([^ ]*).*?n:\s{2}([^ ]*).*?e:\s{3}(10|2|3).*?e:\s{2}([^ ]*).*?n:\s{2}([^ ]*).*?e:\s{2}(.*?)\s{4}.*?e: ([^ ]*).*?ss:\s([^ ]*).*?t:\s{2}([^ ]*).*?ss:\s{2}([^ ]*).*?age:\s([^ ]*)`)
	re4648 := regexp.MustCompile(`(?m)(4648)\t.*Auditing.*?\t([^ ]*)\sN.*?dit.*?\s([^ ]*)\sL.*?e:\s{2}([^ ]*).*?n:\s{2}([^ ]*).*?D:\s{2}([^ ]*).*?e:\s{2}([^ ]*).*?n:\s{2}([^ ]*).*?e:\s([^ ]*).*?n:\s([^ ]*).*?e:\s{2}(.*?)\s{3}N.*?ss:\s([^ ]*).*?t:\s{3}([^ ]*)`)
	re4672 := regexp.MustCompile(`(?m)(4672)\t.*?ing\s([^ ]*)\sN.*?t\s([^ ]*)\sN.*e:\s{2}([^ ]*).*?n:\s{2}(.*?)\s{3}.*?s:\s{2}(.*?)\d`)

	printEvents(re4663)
	printEvents(re4722re4725)
	printEvents(re4720)
	printEvents(re4688)
	printEvents(re5140)
	//printEvents(re7040)
	//printEvents(re7045)
	printEvents(re4624)
	printEvents(re4648)
	printEvents(re4672)

	exec.Command("/bin/bash", "-c", "cat /home/blt15b/win-events-results | mail -s 'Windows Events' blt15b").Output()
}
