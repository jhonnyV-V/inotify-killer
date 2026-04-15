package main

import "core:bytes"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:unicode"

InotifyData :: struct #packed {
	pid:       uint,
	uid:       uint,
	instances: uint,
	watches:   uint,
	name:      string,
}

kernelProvidesWatchesInfo := false
processesData: []InotifyData

sortProcessData :: proc() {
	//select sort, to lazy to do quick sort
	for i := 0; i < len(processesData); i += 1 {
		maxValue := i

		for j := i + 1; j < len(processesData); j += 1 {
			if kernelProvidesWatchesInfo {
				if processesData[j].watches > processesData[maxValue].watches {
					maxValue = j
				}
			} else {
				if processesData[j].instances > processesData[maxValue].instances {
					maxValue = j
				}
			}
		}

		if maxValue != i {
			temp := processesData[i]
			processesData[i] = processesData[maxValue]
			processesData[maxValue] = temp
		}
	}
}

getWatchesFromFile :: proc(filename: string) -> uint {
	data, err := os.read_entire_file_from_path(filename, context.allocator)

	if err != nil {
		return 0
	}

	i := 0
	searchTerm := []byte{'i', 'n', 'o', 't', 'i', 'f', 'y', ' '}
	count: uint = 0

	for i <= len(data) {
		if bytes.compare(data[i:i + len(searchTerm)], searchTerm) == 0 {
			count += 1
		}

		index := bytes.index(data[i:], []u8{'\n'})

		(index != -1) or_break

		i += index + 1

		(i + (len(searchTerm) + 1) <= len(data)) or_break
	}

	return count
}

getUid :: proc(filename: string) -> (uint, os.Error) {
	data, err := os.read_entire_file_from_path(filename, context.allocator)

	if err != nil {
		return 0, err
	}

	i := 0
	searchTerm := []byte{'U', 'i', 'd', ':'}
	foundTerm: string = ""

	for i <= len(data) {
		if bytes.compare(data[i:i + 4], searchTerm) == 0 {
			hasReadFirstNumber := false
			j := i + 5
			for char in data[i + 5:] {
				if bytes.is_space(rune(char)) {
					if hasReadFirstNumber {
						foundTerm = string(data[i + 5:j])
						break
					}
					continue
				}
				hasReadFirstNumber = true
				j += 1
			}
			break
		}

		index := bytes.index(data[i:], []u8{'\n'})

		(index != -1) or_break

		i += index + 1

		(i + 5 <= len(data)) or_break
	}

	uid, ok := strconv.parse_uint(foundTerm)

	if !ok || foundTerm == "" {
		fmt.printf("failed to parse uuid %q\n", foundTerm)
		return 0, nil
	}

	return uid, nil
}

parseInotifyData :: proc() {
	processes, readProcErr := os.read_all_directory_by_path("/proc", context.allocator)
	assert(readProcErr == nil, "failed to read /proc")

	processesData = make([]InotifyData, len(processes), context.allocator)
	defer delete(processesData)
	i: int = 0

	for process in processes {
		(process.type == .Directory) or_continue
		unicode.is_number(rune(process.name[0])) or_continue
		pid, ok := strconv.parse_uint(process.name)
		if !ok {
			fmt.printf("failed to parse %s to uint\n", process.name)
			continue
		}

		execPath, readlinkError := os.read_link(
			fmt.tprintf("/proc/%s/exe", process.name),
			context.allocator,
		)

		if readlinkError != nil {
			if readlinkError != .EACCES && readlinkError != .Not_Exist {
				fmt.printf("failed to readlink of exe for %s: %s\n", process.name, readlinkError)
			}
			continue
		}
		name := filepath.base(execPath)

		uid, readUuidError := getUid(fmt.tprintf("/proc/%s/status", process.name))

		if readUuidError != nil {
			fmt.printf("failed to read uuid for %s: %s\n", process.name, readUuidError)
			continue
		}

		fdFilenames, readFdDirError := os.read_all_directory_by_path(
			fmt.tprintf("/proc/%s/fd", process.name),
			context.allocator,
		)

		if readFdDirError != nil {
			if readFdDirError != .EACCES && readFdDirError != .Not_Exist {
				fmt.printf("failed to read dir fd for %s: %s\n", process.name, readFdDirError)
			}
			continue
		}

		instances: uint = 0
		watches: uint = 0

		for fdFile in fdFilenames {
			(fdFile.type == .Symlink) or_continue

			fdPath, readlinkError := os.read_link(fdFile.fullpath, context.allocator)

			if readlinkError != nil {
				if readlinkError != .EACCES && readlinkError != .Not_Exist {
					fmt.printf(
						"failed to readlink of fd for %s: %s\n",
						process.name,
						readlinkError,
					)
				}
				continue
			}

			fdName := filepath.base(fdPath)

			if fdName == "anon_inode:inotify" || fdName == "inotify" {
				instances += 1
				watches += getWatchesFromFile(
					fmt.tprintf("/proc/%s/fdinfo/%s", process.name, fdFile.name),
				)
			}

			if !kernelProvidesWatchesInfo && watches > 0 {
				kernelProvidesWatchesInfo = true
			}
		}

		(instances > 0) or_continue


		processData := InotifyData {
			pid       = pid,
			name      = name != "" ? name : execPath,
			uid       = uid,
			instances = instances,
			watches   = watches,
		}

		processesData[i] = processData
		i += 1
	}

}

main :: proc() {
	parseInotifyData()
	sortProcessData()
	for process in processesData {
		(process.instances > 0) or_continue
		fmt.printf(
			"%s | intances: %d | watches: %d\n",
			process.name,
			process.instances,
			process.watches,
		)
	}
	//NOTE: temp automatically remove all with 30k watches maybe put this behind some arg or flag
	for process in processesData {
		(process.watches >= 20_000) or_continue

		err := os.process_kill(os.Process{pid = int(process.pid)})

		if err != nil {
			fmt.printf("failed to kill %s %s\n", process.name, err)
		}
	}
	//TODO: tui part check how to termcl with https://github.com/dbrckovi/Simple-File-Commander
}
