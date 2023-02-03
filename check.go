package main

// from cshatag, mods to do MD5 as well as SHA256 by MGTM 20230113

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/xattr"
)

const xattrSha256 = "user.shatag.sha256"
const xattrTsSha256 = "user.shatag.ts"
const zeroSha256 = "0000000000000000000000000000000000000000000000000000000000000000"

const xattrMd5 = "user.shatag.md5"
const xattrTsMd5 = "user.shatag.tsmd5"
const zeroMd5 = "00000000000000000000000000000000"

type fileTimestamp struct {
	s  uint64
	ns uint32
}

func zeroFileTimeStamp() fileTimestamp {
	return fileTimestamp{
		s:  uint64(0),
		ns: uint32(0),
	}
}

func (ts *fileTimestamp) prettyPrint() string {
	return fmt.Sprintf("%010d.%09d", ts.s, ts.ns)
}

type fileAttr struct {
	ts     fileTimestamp
	tsMd5  fileTimestamp
	sha256 []byte
	md5    []byte
}

func (a *fileAttr) prettyPrint() string {
	return fmt.Sprintf("%s %s\nmd5:%s %s", string(a.sha256), a.ts.prettyPrint(), string(a.md5), a.tsMd5.prettyPrint())
}

// getStoredAttr reads the stored extendend attributes from a file. The file
// should look like this:
//
//     $ getfattr -d foo.txt
//     user.shatag.sha256="dc9fe2260fd6748b29532be0ca2750a50f9eca82046b15497f127eba6dda90e8"
//     user.shatag.ts="1560177334.020775051"

func getStoredAttr(bMd5 bool, f *os.File) (attr fileAttr, err error) {
	if bMd5 {
		return getStoredAttrMd5(f)
	} else {
		return getStoredAttrSha256(f)
	}
}

func getStoredAttrSha256(f *os.File) (attr fileAttr, err error) {
	attr.sha256 = []byte(zeroSha256)
	val, err := xattr.FGet(f, xattrSha256)
	if err == nil {
		copy(attr.sha256, val)
	}
	val, err = xattr.FGet(f, xattrTsSha256)
	if err == nil {
		parts := strings.SplitN(string(val), ".", 2)
		attr.ts.s, _ = strconv.ParseUint(parts[0], 10, 64)
		if len(parts) > 1 {
			ns64, _ := strconv.ParseUint(parts[1], 10, 32)
			attr.ts.ns = uint32(ns64)
		}
	}
	return attr, nil
}

func getStoredAttrMd5(f *os.File) (attr fileAttr, err error) {
	attr.md5 = []byte(zeroMd5)
	val, err := xattr.FGet(f, xattrMd5)
	if err == nil {
		copy(attr.md5, val)
	}
	val, err = xattr.FGet(f, xattrTsMd5)
	if err == nil {
		parts := strings.SplitN(string(val), ".", 2)
		attr.tsMd5.s, _ = strconv.ParseUint(parts[0], 10, 64)
		if len(parts) > 1 {
			ns64, _ := strconv.ParseUint(parts[1], 10, 32)
			attr.tsMd5.ns = uint32(ns64)
		}
	}
	return attr, nil
}

// getMtime reads the actual modification time of file "f" from disk.
func getMtime(f *os.File) (ts fileTimestamp, err error) {
	fi, err := f.Stat()
	if err != nil {
		return
	}
	ts.s = uint64(fi.ModTime().Unix())
	ts.ns = uint32(fi.ModTime().Nanosecond())
	return
}

func getActualAttr(bMd5 bool, f *os.File) (attr fileAttr, err error) {
	if bMd5 {
		return getActualAttrMd5(f)
	} else {
		return getActualAttrSha256(f)
	}
}

// getActualAttr reads the actual modification time and hashes the file content.
func getActualAttrMd5(f *os.File) (attr fileAttr, err error) {
	attr.md5 = []byte(zeroMd5)
	attr.tsMd5, err = getMtime(f)
	if err != nil {
		return attr, err
	}
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return attr, err
	}
	// Check if the file was modified while we were computing the hash
	ts2, err := getMtime(f)
	if err != nil {
		return attr, err
	} else if attr.tsMd5 != ts2 {
		return attr, syscall.EINPROGRESS
	}
	attr.md5 = []byte(fmt.Sprintf("%x", h.Sum(nil)))
	return attr, nil
}

// getActualAttr reads the actual modification time and hashes the file content.
func getActualAttrSha256(f *os.File) (attr fileAttr, err error) {
	attr.sha256 = []byte(zeroSha256)
	attr.ts, err = getMtime(f)
	if err != nil {
		return attr, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return attr, err
	}
	// Check if the file was modified while we were computing the hash
	ts2, err := getMtime(f)
	if err != nil {
		return attr, err
	} else if attr.ts != ts2 {
		return attr, syscall.EINPROGRESS
	}
	attr.sha256 = []byte(fmt.Sprintf("%x", h.Sum(nil)))
	return attr, nil
}

func timesMatch(bMd5 bool, stored fileAttr, actual fileAttr) bool {
	if bMd5 && (stored.tsMd5 == actual.tsMd5) {
		return true
	} else if !bMd5 && (stored.ts == actual.ts) {
		return true
	} else {
		return false
	}
}

func timesMatchZero(bMd5 bool, attr fileAttr) bool {
	if bMd5 && (attr.tsMd5 == zeroFileTimeStamp()) {
		return true
	} else if !bMd5 && (attr.ts == zeroFileTimeStamp()) {
		return true
	} else {
		return false
	}
}

func checksumsMatch(bMd5 bool, stored fileAttr, actual fileAttr) bool {
	if bMd5 && bytes.Equal(stored.md5, actual.md5) {
		return true
	} else if !bMd5 && bytes.Equal(stored.sha256, actual.sha256) {
		return true
	} else {
		return false
	}
}

func bytesMatchZero(bMd5 bool, attr fileAttr) bool {
	if bMd5 && bytes.Equal(attr.md5, []byte(zeroMd5)) {
		return true
	} else if !bMd5 && bytes.Equal(attr.sha256, []byte(zeroSha256)) {
		return true
	} else {
		return false
	}
}

func checkFilename(bMd5 bool, pathFile string, actual fileAttr) bool {
	fn := filepath.Base(pathFile)
	hash := []byte("")
	if bMd5 {  // want 32 chars for the hash
		hash = []byte(extractChecksumFromFilename(bMd5, fn, 32))
	} else {
		hash = []byte(extractChecksumFromFilename(bMd5, fn, 0))
	}

	//fmt.Printf( "got hash '%s' from filename:%s\n", hash, fn );
	if bMd5 {
		if bytes.Equal(hash, actual.md5) {
			return true
		}
	} else {
		if bytes.Equal(hash, actual.sha256) {
			return true
		}
	}
	return false
}

func extractChecksumFromFilename(bMd5 bool, fn string, len int) string {
	hash := ""
	if len == 32 {  // match exactly 32 chars
		r, _ := regexp.Compile("[0-9a-fA-F]{32}")
		hash = r.FindString(fn)
	} else {  // any other number means unlimited. MGTM yes lazy
		r, _ := regexp.Compile("[0-9a-fA-F]")
		hash = r.FindString(fn)
	}


	return hash
}

// printComparison prints something like this:
//
//	stored: faa28bfa6332264571f28b4131b0673f0d55a31a2ccf5c873c435c235647bf76 1560177189.769244818
//	actual: dc9fe2260fd6748b29532be0ca2750a50f9eca82046b15497f127eba6dda90e8 1560177334.020775051
func printComparison(stored fileAttr, actual fileAttr) {
	fmt.Printf(" stored: %s\n actual: %s\n", stored.prettyPrint(), actual.prettyPrint())
}

func checkFile(bMd5 bool, fn string) {
	stats.total++
	f, err := os.Open(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		stats.errorsOpening++
		return
	}
	defer f.Close()

	if args.remove {
		if err = removeAttr(f); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			stats.errorsOther++
			return
		}
		if !args.q {
			fmt.Printf("<removed xattr> %s\n", fn)
		}
		stats.ok++
		return
	}

	stored, _ := getStoredAttr(bMd5, f)
	if gBOnlyFilename {
		// do not try to calc actual md5, only use the stored one
		bMatch := checkFilename(bMd5, fn, stored)
		if bMatch {
			if !args.q {
				fmt.Printf("<ok> %s\n", fn)
			}
		} else {
			if !args.qq {
				fmt.Printf("<filename %s does not match md5 %s> %s\n", fn, stored.md5, fn)
			}
		}
	} else {
		// calc actual md5, for comparing to the stored one
		actual, err := getActualAttr(bMd5, f)
		if err == syscall.EINPROGRESS {
			if !args.qq {
				fmt.Printf("<concurrent modification> %s\n", fn)
			}
			stats.inprogress++
			return
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			stats.errorsOther++
			return
		}

		if timesMatch(bMd5, stored, actual) {
			if checksumsMatch(bMd5, stored, actual) {
				bOk := true
				if gBCheckFilename {
					bOk = checkFilename(bMd5, fn, actual)
					if !bOk {
						if !args.q {
							fmt.Printf("<filename not matched> %s\n", fn)
							printComparison(stored, actual)
						}
						return
					}
				}
				if !args.q {
					fmt.Printf("<ok> %s\n", fn)
				}
				stats.ok++
				return
			}
			fmt.Fprintf(os.Stderr, "Error: corrupt file %q\n", fn)
			fmt.Printf("<corrupt> %s\n", fn)
			stats.corrupt++
		} else if checksumsMatch(bMd5, stored, actual) {
			if !args.qq {
				fmt.Printf("<timechange> %s\n", fn)
			}
			stats.timechange++
		} else if bytesMatchZero(bMd5, stored) && timesMatchZero(bMd5, stored) {
			// no metadata indicates a 'new' file
			if !args.qq {
				fmt.Printf("<new> %s\n", fn)
			}
			stats.newfile++
		} else {
			// timestamp is outdated
			if !args.qq {
				fmt.Printf("<outdated> %s\n", fn)
			}
			stats.outdated++
		}
		if !args.qq {
			printComparison(stored, actual)
		}
		err = storeAttr(bMd5, f, actual)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			stats.errorsWritingXattr++
			return
		}
	}

}
