package ebpftracer

import (
	"bufio"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/exp/maps"
	"k8s.io/klog/v2"
)

func (t *Tracer) AttachNodejsProbes(pid uint32, exe string) *UprobeKey {
	log := func(libPath, msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			if !t.firstUprobeFailure(libPath) {
				return
			}
			klog.WarningfDepth(1, "pid=%d lib=%s: %s: %s. The optional Node.js metric (container_nodejs_event_loop_blocked_time_seconds_total) won't be collected for processes using this file. Other metrics are not affected.", pid, libPath, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d lib=%s: %s", pid, libPath, msg)
	}

	for _, libPath := range append(getMappedLibs(pid, "libuv"), proc.Path(pid, "root", exe)) {
		key, ok := t.AcquireGlobalUprobe(libPath, func() []link.Link {
			links, err := t.attachNodejsUprobes(libPath)
			if err != nil {
				log(libPath, "failed to attach Node.js uprobes", err)
				return nil
			}
			log(libPath, "nodejs uprobes attached", nil)
			// a file is attached once, and official builds have libuv and TLSWrap in the same node executable
			return append(links, t.attachNodejsTlsUprobes(libPath, uprobeLog(pid, ""))...)
		})
		if ok {
			return &key
		}
	}
	return nil
}

func (t *Tracer) AttachNodejsTlsUprobes(pid uint32, exe string) *UprobeKey {
	log := uprobeLog(pid, "")
	for _, libPath := range append([]string{proc.Path(pid, "root", exe)}, getMappedLibs(pid, "libnode")...) {
		key, ok := t.AcquireGlobalUprobe(libPath, func() []link.Link {
			return t.attachNodejsTlsUprobes(libPath, log)
		})
		if ok {
			return &key
		}
	}
	return nil
}

func (t *Tracer) attachNodejsTlsUprobes(libPath string, log func(string, error)) []link.Link {
	if t.disableL7Tracing {
		return nil
	}
	ef, err := OpenELFFile(libPath)
	if err != nil {
		log("open elf", err)
		return nil
	}
	defer ef.Close()

	links := t.attachUprobes(libPath, ef, nodejsTlsUprobes(ef), log)
	if len(links) > 0 {
		log("nodejs tls uprobes attached", nil)
	}
	return links
}

func nodejsTlsUprobes(ef *ELFFile) []uprobeSpec {
	var specs []uprobeSpec
	for _, s := range []uprobeSpec{
		{symbol: "_ZN4node6crypto7TLSWrap13OnStreamAllocEm", uprobe: "nodejs_tls_stream_alloc_enter"},
		{symbol: "_ZN4node6crypto7TLSWrap12OnStreamReadElRK8uv_buf_t", uprobe: "nodejs_tls_stream_read_enter"},
	} {
		if thunk := ef.FindSymbolBySubstrings("_ZThn", strings.TrimPrefix(s.symbol, "_Z")); thunk != nil {
			s.symbol = thunk.Name()
		}
		specs = append(specs, s)
	}
	if _, err := ef.GetSymbol("SSL_write"); err == nil {
		specs = append(specs, openSslUprobes...)
	}
	return specs
}

func (t *Tracer) attachNodejsUprobes(libPath string) ([]link.Link, error) {
	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, err
	}
	ef, err := OpenELFFile(libPath)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	s, err := ef.GetSymbol("uv__io_poll")
	if err != nil {
		return nil, err
	}
	l, err := s.AttachUprobe(exe, t.uprobes["uv_io_poll_enter"], 0)
	if err != nil {
		return nil, err
	}
	var links []link.Link
	links = append(links, l)

	ls, err := s.AttachUretprobes(exe, t.uprobes["uv_io_poll_exit"], 0)
	links = append(links, ls...)
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, err
	}

	for _, cb := range []string{"uv__stream_io", "uv__async_io", "uv__poll_io", "uv__server_io", "uv__udp_io"} {
		s, err = ef.GetSymbol(cb)
		if err != nil {
			break
		}
		l, err = s.AttachUprobe(exe, t.uprobes["uv_io_cb_enter"], 0)
		if err != nil {
			break
		}
		links = append(links, l)
		ls, err = s.AttachUretprobes(exe, t.uprobes["uv_io_cb_exit"], 0)
		links = append(links, ls...)
		if err != nil {
			break
		}
	}
	return links, nil
}

func getMappedLibs(pid uint32, name string) []string {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	libs := map[string]bool{}
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		if strings.Contains(libPath, name) {
			libs[proc.Path(pid, "root", libPath)] = true
		}
	}
	return maps.Keys(libs)
}
