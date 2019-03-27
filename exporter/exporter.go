package exporter

import (
	"github.com/libvirt/libvirt-go"
	"github.com/libvirt/libvirt-go-xml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"strings"
)

// Listed available metrics

type Exporter struct {
	gauges                   map[string]prometheus.Gauge
	counter                  map[string]prometheus.Counter
	counterVecs              map[string]*prometheus.CounterVec
	gaugeVecs                map[string]*prometheus.GaugeVec
}

var ConnectUrl string


func NewExporter(namespace string) *Exporter {
	//
	//gauges := make(map[string]prometheus.Gauge)
	//counter := make(map[string]prometheus.Counter)
	counterVecs := make(map[string]*prometheus.CounterVec)
	gaugeVecs := make(map[string]*prometheus.GaugeVec)


	// get cpu
	counterVecs["cpu_time"] = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "cpu_time",
		Help:      "cpu time."}, []string{"instance_uuid", "node"})

	// memory

	gaugeVecs["status"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "status",
		Help:      "instance status."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_swap_out"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_swap_out",
		Help:      "The total amount of memory written out to swap space (in kB)."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_swap_in"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_swap_in",
		Help:      "The total amount of data read from swap space (in kB)."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_major_fault"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_major_fault",
		Help:      "Page faults occur when a process makes a valid access to virtual memory that is not available. When servicing the page fault, if disk IO is required, it is considered a major fault. If not, it is a minor fault. These are expressed as the number of faults that have occurred."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_minor_fault"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_minor_fault",
		Help:      "The total amount of data read from swap space (in kB)."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_unused"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_unused",
		Help:      "The amount of memory left completely unused by the system. Memory that is available but used for reclaimable caches should NOT be reported as free. This value is expressed in kB."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_available"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_available",
		Help:      "The total amount of usable memory as seen by the domain. This value may be less than the amount of memory assigned to the domain if a balloon driver is in use or if the guest OS does not initialize all assigned pages. This value is expressed in kB."}, []string{"instance_uuid", "node"})


	gaugeVecs["memory_stat_last_update"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_last_update",
		Help:      "Timestamp of the last update of statistics, in seconds."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_actual_balloon"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_actual_balloon",
		Help:      "Current balloon value (in KB)."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_rss"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_rss",
		Help:      "Resident Set Size of the process running the domain. This value is in kB."}, []string{"instance_uuid", "node"})

	gaugeVecs["memory_stat_usable"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stat_usable",
		Help:      "How much the balloon can be inflated without pushing the guest system to swap, corresponds to 'Available' in /proc/meminfo."}, []string{"instance_uuid", "node"})


    // disk

	gaugeVecs["disk_read_iops"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "disk_read_iops",
		Help:      "number of read requests."}, []string{"instance_uuid", "node", "dev", "uuid"})

	gaugeVecs["disk_read_bytes"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "disk_read_bytes",
		Help:      "number of read byte."}, []string{"instance_uuid", "node", "dev", "uuid"})

	gaugeVecs["disk_write_iops"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "disk_write_iops",
		Help:      "number of write requests."}, []string{"instance_uuid", "node", "dev", "uuid"})

	gaugeVecs["disk_write_bytes"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "disk_write_bytes",
		Help:      "number of written bytes."}, []string{"instance_uuid", "node", "dev", "uuid"})

	gaugeVecs["disk_errs"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "disk_errs",
		Help:      "In Xen this returns the mysterious oo_req."}, []string{"instance_uuid", "node", "dev", "uuid"})

	// network

	gaugeVecs["network_rx_bytes"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "network_rx_bytes",
		Help:      "Number of bytes received."}, []string{"instance_uuid", "node", "dev"})

	gaugeVecs["network_tx_bytes"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "network_tx_bytes",
		Help:      "Number of bytes transferred."}, []string{"instance_uuid", "node", "dev"})


	gaugeVecs["network_rx_packets"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "network_rx_packets",
		Help:      "Received packet data."}, []string{"instance_uuid", "node", "dev"})

	gaugeVecs["network_tx_packets"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "network_tx_packets",
		Help:      "Number of packets transmitted."}, []string{"instance_uuid", "node", "dev"})

	gaugeVecs["network_rx_drop"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "network_rx_drop",
		Help:      "The amount of data dropped when a packet is received."}, []string{"instance_uuid", "node", "dev"})

	gaugeVecs["network_tx_drop"] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "network_tx_drop",
		Help:      "The amount of data dropped by a transmission packet"}, []string{"instance_uuid", "node", "dev"})




	return &Exporter{
		//gauges: gauges,
		//counter: counter,
		counterVecs: counterVecs,
		gaugeVecs: gaugeVecs,
	}
}
func (e *Exporter) collectData(connectUrl string) {

	// tcp libvirt

	conn, err := libvirt.NewConnect(connectUrl)

	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()

	hostname, err := conn.GetHostname()
	if err != nil {
		log.Fatalln(err)
	}


	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_RUNNING)
	if err != nil {
		log.Fatalln(err)
	}

	for _, dom := range doms {
		info, err := dom.GetInfo()
		if err != nil {
			log.Fatalln(err)
		}

		uuid, err := dom.GetUUIDString()
		if err != nil {
			log.Fatalln(err)
		}

		id, err := dom.GetID()
		if err != nil {
			log.Fatalln(err)
		}

		xml , err:= dom.GetXMLDesc(0)
		if err != nil {
			log.Fatalln(err)
		}

		domcfg := &libvirtxml.Domain{}

		err = domcfg.Unmarshal(xml)
		if err != nil {
			log.Fatalln(err)
		}

		// get Memory
		mem, err := dom.MemoryStats(uint32(id), 0)
		if err != nil {
			log.Fatalln(err)
		}

		for _, m := range mem {
			switch m.Tag {
			case 0:
				e.gaugeVecs["memory_stat_swap_in"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 1:
				e.gaugeVecs["memory_stat_swap_out"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 2:
				e.gaugeVecs["memory_stat_major_fault"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 3:
				e.gaugeVecs["memory_stat_minor_fault"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 4:
				e.gaugeVecs["memory_stat_unused"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 5:
				e.gaugeVecs["memory_stat_available"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 6:
				e.gaugeVecs["memory_stat_actual_balloon"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 7:
				e.gaugeVecs["memory_stat_rss"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 8:
				e.gaugeVecs["memory_stat_usable"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))
			case 9:
				e.gaugeVecs["memory_stat_last_update"].With(prometheus.Labels{
					"instance_uuid": uuid,
					"node": hostname,
				}).Set(float64(m.Val))

			}
		}

		//get disk

		for _, disk := range domcfg.Devices.Disks {

			blockStatus, err := dom.BlockStats(disk.Target.Dev)
			if err != nil {
				log.Fatalln(err)
			}

			volumeId := SplitUuid(disk.Source.Network.Name)

			e.gaugeVecs["disk_read_iops"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": disk.Target.Dev,
				"uuid": volumeId,
			}).Set(float64(blockStatus.RdReq))

			e.gaugeVecs["disk_read_bytes"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": disk.Target.Dev,
				"uuid": volumeId,
			}).Set(float64(blockStatus.RdBytes))

			e.gaugeVecs["disk_write_iops"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": disk.Target.Dev,
				"uuid": volumeId,
			}).Set(float64(blockStatus.WrReq))

			e.gaugeVecs["disk_write_bytes"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": disk.Target.Dev,
				"uuid": volumeId,
			}).Set(float64(blockStatus.WrBytes))

			e.gaugeVecs["disk_errs"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": disk.Target.Dev,
				"uuid": volumeId,
			}).Set(float64(blockStatus.Errs))

		}


		for _, network := range domcfg.Devices.Interfaces {
			interfaceStatus, err := dom.InterfaceStats(network.Target.Dev)
			if err != nil {
				log.Fatalln(err)
			}

			e.gaugeVecs["network_rx_bytes"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": network.Target.Dev,
			}).Set(float64(interfaceStatus.RxBytes))

			e.gaugeVecs["network_tx_bytes"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": network.Target.Dev,
			}).Set(float64(interfaceStatus.TxBytes))

			e.gaugeVecs["network_tx_packets"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": network.Target.Dev,
			}).Set(float64(interfaceStatus.TxPackets))

			e.gaugeVecs["network_rx_packets"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": network.Target.Dev,
			}).Set(float64(interfaceStatus.RxPackets))

			e.gaugeVecs["network_rx_drop"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": network.Target.Dev,
			}).Set(float64(interfaceStatus.RxDrop))

			e.gaugeVecs["network_tx_drop"].With(prometheus.Labels{
				"instance_uuid": uuid,
				"node": hostname,
				"dev": network.Target.Dev,
			}).Set(float64(interfaceStatus.TxDrop))

		}

		// https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainGetHostname
		e.counterVecs["cpu_time"].With(prometheus.Labels{
			"instance_uuid": uuid,
			"node": hostname,
		}).Add(float64(info.CpuTime))

		e.gaugeVecs["status"].With(prometheus.Labels{
			"instance_uuid": uuid,
			"node": hostname,
		}).Set(float64(info.State))

		dom.Free()

	}


}


func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {

	for _, value := range e.gaugeVecs {
		value.Describe(ch)
	}


	for _, value := range e.counterVecs {
		value.Describe(ch)
	}

}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.collectData(ConnectUrl)

	for _, value := range e.gaugeVecs{
		value.Collect(ch)
	}

	for _, value := range e.counterVecs {
		value.Collect(ch)
	}
}

func SplitUuid(name string) (volumeId string) {

	s := strings.Split(name, "/")

	if strings.HasPrefix(s[1], "volume-") {
		volumeId = strings.TrimPrefix(s[1], "volume-")
	} else if strings.HasSuffix(s[1], "_disk") {
		volumeId = strings.TrimSuffix(s[1], "_disk")
	} else if strings.HasSuffix(s[1], "_disk.config"){
		volumeId = strings.TrimSuffix(s[1], "_disk.config")
	} else {
		volumeId = s[1]
	}

	return volumeId

}