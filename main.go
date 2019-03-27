package main

import (
	"github.com/prometheus/common/log"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
	"openstack-exporter/exporter"
	"net/http"
)

func main()  {

	var (
		bind           = kingpin.Flag("web.listen-address", "address:port to listen on").Default(":8098").String()
		uri            = kingpin.Flag("uri", "libvirt used connection URIs " +
			"default:   qemu:///system" +
			"qemu+ssh:  qemu+ssh://root@sleet.cloud.example.com/system " +
			"qemu+unix: qemu+unix:///system?socket=/opt/libvirt/run/libvirt/libvirt-sock" +
			"qemu+tcp:  qemu+tcp://root@sleet.cloud.example.com:port/system").Default("qemu:///system").String()

		prefix         = kingpin.Flag("prefix", "Prefix for metrics").Default("openstack_instance").String()

	)

	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	exporter.ConnectUrl = *uri
	metricsPath := "/metrics"

	exporters := exporter.NewExporter(*prefix)

	prometheus.Register(exporters)

	http.Handle(metricsPath, prometheus.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Openstack exporter</title></head>
             <body>
             <h1>Openstack Exporter</h1>
             <p><a href='/metrics'>Metrics</a></p>
             </body>
             </html>`))
	})

	log.Infof("Starting HTTP server on", *bind)
	log.Fatal(http.ListenAndServe(*bind, nil))

}