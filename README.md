# k8s-proxy

this is a reverse-proxy for a kubernetes endpoint that allows
using kubectl exec. it's supposed to be simple to so people can
understand what's required to support kubectl exec through a proxy.

mainly taken from: https://github.com/openshift/origin/blob/v1.2.0/pkg/util/httpproxy/upgradeawareproxy.go

how to use me:

    go run main.go \
      -listen <LOCAL ENDPOINT>
      -target <TARGET CLUSTER>
      [-insecure]

e.g.

    go run main.go \
      -listen http://127.0.0.1:8080 \
      -target https://123.123.123.123 \
      -insecure

then you target your kubectl at your local endpoint, e.g.

    kubectl \
      --kubeconfig=/dev/null \
      --server=https://127.0.0.1:8443 \
      --insecure-skip-tls-verify \
      --username=username \
      --password=password \
      exec -i --tty podname sh

gives you an interactive shell in your container through a go proxy

important to notice here is that we have to run our local server with tls because
kubectl will drop --token or --username and --password from the request
if --server is not https://...

you can use socat to forward a tls enabled endpoint to this proxy, e.g.

    socat -v openssl-listen:8443,cert=server.pem,verify=0,reuseaddr,fork tcp4:localhost:8080
