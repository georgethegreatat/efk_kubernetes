# Elasticsearch Cloud & Fluent Bit & Kibana in Kubernetes

Hi everyone. 
Here I want to show you how to simply configure and deploy EFK
stack on your Kubernetes cluster using Elastic Cloud as Elasticsearch vendor.

###### Versions
```
Elasticsearch   - v7.14.0 (Elastic Cloud Instance)
Fluent Bit      - v1.8.7
Kibana          - v7.9.2 (latest available for LogTrail plugin)
LogTrail Plugin - v0.1.31
Kubernetes      - v.1.14 / v.1.19 (tested on bouth)
```

###### Note for Kubernetes < v1.16
```
For Kubernetes versions older than v1.16, the DaemonSet resource is not available on apps/v1 , 
the resource is available on apiVersion: extensions/v1beta1 . Our current Daemonset Yaml files uses the new apiVersion.
If you are using and older Kubernetes version, manually grab a copy of your Daemonset Yaml file and 
replace the value of apiVersion from:

> apiVersion: apps/v1

To:

> apiVersion: extensions/v1beta1
```
[Official Documentation](https://docs.fluentbit.io/manual/installation/kubernetes)

### Step #1. Elasticsearch

You need to define the next secrets from your Elastic Cloud:

```
CLOUD_ELASTICSEARCH_ID
CLOUD_ELASTICSEARCH_HOST
CLOUD_ELASTICSEARCH_PORT
CLOUD_ELASTICSEARCH_USERNAME
CLOUD_ELASTICSEARCH_PASSWORD
```

### Step #2. Secret data

In this step you need define configmap and secret for Fluent Bit environment to send the data to Elasticsearch.
Please define the values of variables what you will see below.

Create the `elasticsearch-configmap.yaml`:

```
kind: ConfigMap
apiVersion: v1
metadata:
  name: elasticsearch-configmap
  namespace: logging
data:
  CLOUD_ELASTICSEARCH_ID: 'CLOUD_ELASTICSEARCH_ID'
  CLOUD_ELASTICSEARCH_HOST: 'CLOUD_ELASTICSEARCH_HOST'
  CLOUD_ELASTICSEARCH_PORT: 'CLOUD_ELASTICSEARCH_PORT'
```

And `elasticsearch-secret.yaml`:

```
kind: Secret
apiVersion: v1beta1
metadata:
  name: elasticsearch-secret
  namespace: logging
data:
  CLOUD_ELASTICSEARCH_PASSWORD: 'CLOUD_ELASTICSEARCH_PASSWORD'
  CLOUD_ELASTICSEARCH_USER: 'CLOUD_ELASTICSEARCH_USERNAME'
type: Opaque
```
> Please note, you need to change namespace from 'logging' to your namespace where the fluent bit will be located.  

Great! Now you can apply this configuration using next commands:
```
kubectl create -f elasticsearch-configmap.yaml
kubectl create -f elasticsearch-secret.yaml
```

### Step #3. Fluent Bit Deployment

After you create the secrets, configmap, defined what kubernetes version you have 
you are ready to go ahead, so let's do it.

Create `fluent-bit-role.yaml`:

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fluent-bit-read
rules:
- apiGroups: [""]
  resources:
  - namespaces
  - pods
  verbs: ["get", "list", "watch"]
```

Create `fluent-bit-role-binding.yaml`:

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: fluent-bit-read
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: fluent-bit-read
subjects:
- kind: ServiceAccount
  name: fluent-bit
  namespace: logging
```

> Note this is the main configuration file in your Fluent Bit. Define the variables carefully.

In this example imagine that we have some namespaces: namespace1, namespace2, namespace3, namespace4 with 
different applications running there and our developers team want to get the fresh logs from each one of them.
That's mean we need to define 4 different inputs, filter and outputs parts of code & don't forget about nginx and kube-system namespaces with different logs.


Create `fluent-bit-configmap.yaml`:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: logging
  labels:
    k8s-app: fluent-bit
data:
  # Configuration files: server, input, filters and output
  # ======================================================
  fluent-bit.conf: |
    [SERVICE]
        Flush                     1
        Log_Level                 info
        Daemon                    off
        Parsers_File              parsers.conf
        HTTP_Server               On
        HTTP_Listen               0.0.0.0
        HTTP_Port                 2020
        storage.path              /var/log/flb-storage/
        storage.sync              normal
        storage.checksum          off
        storage.backlog.mem_limit 10M
    @INCLUDE input-kubernetes.conf
    @INCLUDE filter-kubernetes.conf
    @INCLUDE output-elasticsearch.conf
  input-kubernetes.conf: |
    [INPUT]
        Name              tail
        Tag               gold*
        Path              /var/log/containers/*_namespace1_*.log
        Parser            docker
        DB                /var/log/flb_namespace1.db
        Mem_Buf_Limit     10MB
        Skip_Long_Lines   On
        Refresh_Interval  10
        storage.type      filesystem
    [INPUT]
        Name              tail
        Tag               amber*
        Path              /var/log/containers/*_namespace2_*.log
        Parser            docker
        DB                /var/log/flb_namespace2.db
        Mem_Buf_Limit     10MB
        Skip_Long_Lines   On
        Refresh_Interval  10
        storage.type      filesystem
    [INPUT]
        Name              tail
        Tag               black*
        Path              /var/log/containers/*_namespace3_*.log
        Parser            docker
        DB                /var/log/flb_namespace3.db
        Mem_Buf_Limit     10MB
        Skip_Long_Lines   On
        Refresh_Interval  10
        storage.type      filesystem
    [INPUT]
        Name              tail
        Tag               opal*
        Path              /var/log/containers/*_namespace4_*.log
        Parser            docker
        DB                /var/log/flb_namespace4.db
        Mem_Buf_Limit     10MB
        Skip_Long_Lines   On
        Refresh_Interval  10
        storage.type      filesystem
    [INPUT]
        Name              tail
        Tag               nginx*
        Path              /var/log/containers/*nginx*.log
        Parser            nginx
        DB                /var/log/flb_nginx.db
        Mem_Buf_Limit     10MB
        Skip_Long_Lines   On
        Refresh_Interval  10
        storage.type      filesystem
    [INPUT]
        Name              tail
        Tag               kube-system*
        Path              /var/log/containers/*kube-system*.log
        Parser            docker
        DB                /var/log/flb_kubesystem.db
        Mem_Buf_Limit     10MB
        Skip_Long_Lines   On
        Refresh_Interval  10
        storage.type      filesystem
  filter-kubernetes.conf: |
    [FILTER]
        Name                kubernetes
        Match               namespace1*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     namespace1.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
        Annotations         Off
        Labels              On
    [FILTER]
        Name                kubernetes
        Match               namespace2*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     namespace2.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
        Annotations         Off
        Labels              On
    [FILTER]
        Name                kubernetes
        Match               namespace3*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     namespace3.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
        Annotations         Off
        Labels              On
    [FILTER]
        Name                kubernetes
        Match               namespace4*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     namespace4.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
        Annotations         Off
        Labels              On
    [FILTER]
        Name                kubernetes
        Match               nginx*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     nginx.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
        Annotations         Off
        Labels              On
    [FILTER]
        Name                kubernetes
        Match               kube-system*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     kube-system.var.log.containers.
        Merge_Log           On
        Merge_Log_Key       log_processed
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off
        Annotations         Off
        Labels              On
  output-elasticsearch.conf: |
    [OUTPUT]
        Name            es
        Match           namespace1*
        Host            ${CLOUD_ELASTICSEARCH_HOST}
        Port            ${CLOUD_ELASTICSEARCH_PORT}
        Cloud_ID        ${CLOUD_ELASTICSEARCH_ID}
        Cloud_Auth      ${CLOUD_ELASTICSEARCH_USER}:${CLOUD_ELASTICSEARCH_PASSWORD}
        Logstash_Format On
        Logstash_Prefix namespace1
        Replace_Dots    On
        Retry_Limit     False
        tls             On
        tls.verify      Off
        storage.total_limit_size 10M
    [OUTPUT]
        Name            es
        Match           namespace2*
        Host            ${CLOUD_ELASTICSEARCH_HOST}
        Port            ${CLOUD_ELASTICSEARCH_PORT}
        Cloud_ID        ${CLOUD_ELASTICSEARCH_ID}
        Cloud_Auth      ${CLOUD_ELASTICSEARCH_USER}:${CLOUD_ELASTICSEARCH_PASSWORD}
        Logstash_Format On
        Logstash_Prefix namespace2
        Replace_Dots    On
        Retry_Limit     False
        tls             On
        tls.verify      Off
        storage.total_limit_size 10M
    [OUTPUT]
        Name            es
        Match           namespace3*
        Host            ${CLOUD_ELASTICSEARCH_HOST}
        Port            ${CLOUD_ELASTICSEARCH_PORT}
        Cloud_ID        ${CLOUD_ELASTICSEARCH_ID}
        Cloud_Auth      ${CLOUD_ELASTICSEARCH_USER}:${CLOUD_ELASTICSEARCH_PASSWORD}
        Logstash_Format On
        Logstash_Prefix namespace3
        Replace_Dots    On
        Retry_Limit     False
        tls             On
        tls.verify      Off
        storage.total_limit_size 10M
    [OUTPUT]
        Name            es
        Match           namespace4*
        Host            ${CLOUD_ELASTICSEARCH_HOST}
        Port            ${CLOUD_ELASTICSEARCH_PORT}
        Cloud_ID        ${CLOUD_ELASTICSEARCH_ID}
        Cloud_Auth      ${CLOUD_ELASTICSEARCH_USER}:${CLOUD_ELASTICSEARCH_PASSWORD}
        Logstash_Format On
        Logstash_Prefix namespace4
        Replace_Dots    On
        Retry_Limit     False
        tls             On
        tls.verify      Off
        storage.total_limit_size 10M
    [OUTPUT]
        Name            es
        Match           nginx*
        Host            ${CLOUD_ELASTICSEARCH_HOST}
        Port            ${CLOUD_ELASTICSEARCH_PORT}
        Cloud_ID        ${CLOUD_ELASTICSEARCH_ID}
        Cloud_Auth      ${CLOUD_ELASTICSEARCH_USER}:${CLOUD_ELASTICSEARCH_PASSWORD}
        Logstash_Format On
        Logstash_Prefix nginx
        Replace_Dots    On
        Retry_Limit     False
        tls             On
        tls.verify      Off
        storage.total_limit_size 10M
    [OUTPUT]
        Name            es
        Match           kube-system*
        Host            ${CLOUD_ELASTICSEARCH_HOST}
        Port            ${CLOUD_ELASTICSEARCH_PORT}
        Cloud_ID        ${CLOUD_ELASTICSEARCH_ID}
        Cloud_Auth      ${CLOUD_ELASTICSEARCH_USER}:${CLOUD_ELASTICSEARCH_PASSWORD}
        Logstash_Format On
        Logstash_Prefix kube-system
        Replace_Dots    On
        Retry_Limit     False
        tls             On
        tls.verify      Off
        storage.total_limit_size 10M
  parsers.conf: |
    [PARSER]
        Name   apache
        Format regex
        Regex  ^(?<host>[^ ]*) [^ ]* (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
        Time_Key time
        Time_Format %d/%b/%Y:%H:%M:%S %z
    [PARSER]
        Name   apache2
        Format regex
        Regex  ^(?<host>[^ ]*) [^ ]* (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^ ]*) +\S*)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
        Time_Key time
        Time_Format %d/%b/%Y:%H:%M:%S %z
    [PARSER]
        Name   apache_error
        Format regex
        Regex  ^\[[^ ]* (?<time>[^\]]*)\] \[(?<level>[^\]]*)\](?: \[pid (?<pid>[^\]]*)\])?( \[client (?<client>[^\]]*)\])? (?<message>.*)$
    [PARSER]
        Name   nginx
        Format regex
        Regex ^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
        Time_Key time
        Time_Format %d/%b/%Y:%H:%M:%S %z
    [PARSER]
        Name   json
        Format json
        Time_Key time
        Time_Format %d/%b/%Y:%H:%M:%S %z
    [PARSER]
        Name        docker
        Format      json
        Time_Key    time
        Time_Format %Y-%m-%dT%H:%M:%S.%L
        Time_Keep   On
    [PARSER]
        Name        syslog
        Format      regex
        Regex       ^\<(?<pri>[0-9]+)\>(?<time>[^ ]* {1,2}[^ ]* [^ ]*) (?<host>[^ ]*) (?<ident>[a-zA-Z0-9_\/\.\-]*)(?:\[(?<pid>[0-9]+)\])?(?:[^\:]*\:)? *(?<message>.*)$
        Time_Key    time
        Time_Format %b %d %H:%M:%S
```

Fluent Bit configuration done. It's time to deploy it in Kubernetes:

```
kubectl create -f fluent-bit-service-account.yaml
kubectl create -f fluent-bit-role.yaml
kubectl create -f fluent-bit-role-binding.yaml
kubectl create -f fluent-bit-configmap.yaml
kubectl create -f fluent-bit-ds.yaml
```

Once you'll deploy all the manifests it'll start send the logs to Elasticsearch.
Time to deploy something to Visualize it.

### Step #4. Kibana

I decided to use LogTrail plugin because Developers on my Project want to 
view fresh latest logs from few clusters / few environments in one place without a headache.
Unfortunately LogTrail is a deprecated module for Kibana, but I did not find solution what could be better than it.

Create `logtrail.yaml`:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: logtrail-config
  namespace: infra-monitoring
data:
  logtrail.json: |
    {
      "version": 2,
      "index_patterns": [
        {
          "es": {
            "default_index": "namespace1-*"
          },
          "tail_interval_in_seconds": 10,
          "es_index_time_offset_in_seconds": 0,
          "display_timezone": "local",
          "display_timestamp_format": "MMM DD HH:mm:ss",
          "max_buckets": 500,
          "default_time_range_in_days": 0,
          "max_hosts": 100,
          "max_events_to_keep_in_viewer": 5000,
          "default_search": "",
          "fields": {
            "message_format": "{{{log}}}",
            "mapping": {
                "timestamp": "@timestamp",
                "hostname": "kubernetes.labels.app",
                "program": "kubernetes.pod_name",
                "message": "log"
            }
          },
          "color_mapping": {
            "field": "logLevel",
            "mapping": {
              "error": "#FF0000",
              "warn": "#FFEF96",
              "debug": "#B5E7A0",
              "trace": "#CFE0E8"
            }
          }
        },
        {
          "es": {
            "default_index": "namespace2-*"
          },
          "tail_interval_in_seconds": 10,
          "es_index_time_offset_in_seconds": 0,
          "display_timezone": "local",
          "display_timestamp_format": "MMM DD HH:mm:ss",
          "max_buckets": 500,
          "default_time_range_in_days": 0,
          "max_hosts": 100,
          "max_events_to_keep_in_viewer": 5000,
          "default_search": "",
          "fields": {
            "message_format": "{{{log}}}",
            "mapping": {
                "timestamp": "@timestamp",
                "hostname": "kubernetes.labels.app",
                "program": "kubernetes.pod_name",
                "message": "log"
            }
          },
          "color_mapping": {
            "field": "logLevel",
            "mapping": {
              "error": "#FF0000",
              "warn": "#FFEF96",
              "debug": "#B5E7A0",
              "trace": "#CFE0E8"
            }
          }
        },
        {
          "es": {
            "default_index": "namespace3-*"
          },
          "tail_interval_in_seconds": 10,
          "es_index_time_offset_in_seconds": 0,
          "display_timezone": "local",
          "display_timestamp_format": "MMM DD HH:mm:ss",
          "max_buckets": 500,
          "default_time_range_in_days": 0,
          "max_hosts": 100,
          "max_events_to_keep_in_viewer": 5000,
          "default_search": "",
          "fields": {
            "message_format": "{{{log}}}",
            "mapping": {
                "timestamp": "@timestamp",
                "hostname": "kubernetes.labels.app",
                "program": "kubernetes.pod_name",
                "message": "log"
            }
          },
          "color_mapping": {
            "field": "logLevel",
            "mapping": {
              "error": "#FF0000",
              "warn": "#FFEF96",
              "debug": "#B5E7A0",
              "trace": "#CFE0E8"
            }
          }
        },
        {
          "es": {
            "default_index": "namespace4-*"
          },
          "tail_interval_in_seconds": 10,
          "es_index_time_offset_in_seconds": 0,
          "display_timezone": "local",
          "display_timestamp_format": "MMM DD HH:mm:ss",
          "max_buckets": 500,
          "default_time_range_in_days": 0,
          "max_hosts": 100,
          "max_events_to_keep_in_viewer": 5000,
          "default_search": "",
          "fields": {
            "message_format": "{{{log}}}",
            "mapping": {
                "timestamp": "@timestamp",
                "hostname": "kubernetes.labels.app",
                "program": "kubernetes.pod_name",
                "message": "log"
            }
          },
          "color_mapping": {
            "field": "logLevel",
            "mapping": {
              "error": "#FF0000",
              "warn": "#FFEF96",
              "debug": "#B5E7A0",
              "trace": "#CFE0E8"
            }
          }
        },
        {
          "es": {
            "default_index": "nginx-*"
          },
          "tail_interval_in_seconds": 10,
          "es_index_time_offset_in_seconds": 0,
          "display_timezone": "local",
          "display_timestamp_format": "MMM DD HH:mm:ss",
          "max_buckets": 500,
          "default_time_range_in_days": 0,
          "max_hosts": 100,
          "max_events_to_keep_in_viewer": 5000,
          "default_search": "",
          "fields": {
            "message_format": "{{{log}}}",
            "mapping": {
                "timestamp": "@timestamp",
                "hostname": "kubernetes.labels.app",
                "program": "kubernetes.pod_name",
                "message": "log"
            }
          },
          "color_mapping": {
            "field": "logLevel",
            "mapping": {
              "error": "#FF0000",
              "warn": "#FFEF96",
              "debug": "#B5E7A0",
              "trace": "#CFE0E8"
            }
          }
        },
        {
          "es": {
            "default_index": "kube-system-*"
          },
          "tail_interval_in_seconds": 10,
          "es_index_time_offset_in_seconds": 0,
          "display_timezone": "local",
          "display_timestamp_format": "MMM DD HH:mm:ss",
          "max_buckets": 500,
          "default_time_range_in_days": 0,
          "max_hosts": 100,
          "max_events_to_keep_in_viewer": 5000,
          "default_search": "",
          "fields": {
            "message_format": "{{{log}}}",
            "mapping": {
                "timestamp": "@timestamp",
                "hostname": "kubernetes.labels.app",
                "program": "kubernetes.pod_name",
                "message": "log"
            }
          },
          "color_mapping": {
            "field": "logLevel",
            "mapping": {
              "error": "#FF0000",
              "warn": "#FFEF96",
              "debug": "#B5E7A0",
              "trace": "#CFE0E8"
            }
          }
        }
      ]
    }
```

> Now you need to deploy it: kubectl create -f logtrail.yml 

Create & Deploy `kibana-secret.yaml`:
```
apiVersion: v1
kind: Secret
metadata:
  name: elastic-eu
  namespace: infrastructure
type: Opaque
data:
  # Elasticsearch admin user, password and host
  ELASTICSEARCH_USERNAME: CLOUD_ELASTICSEARCH_USERNAME
  ELASTICSEARCH_PASSWORD: CLOUD_ELASTICSEARCH_PASSWORD
  ELASTICSEARCH_HOSTS: CLOUD_ELASTICSEARCH_HOST
```

Before you'll deploy the kibana you need to add the latest helm repo:
```
helm repo add stable https://charts.helm.sh/stable
```

Create `kibana.yaml`:
```
Notes.
In this file we need to define three variables, Tag of kibana image version and 
LogTrail version & GitHub release link (under the plugins - values) and Kibana URL 
(under the ingress settings).
```

```
image:
  repository: kibana
  tag: 7.9.2
  pullPolicy: IfNotPresent

envFromSecrets: 
  ELASTICSEARCH_USERNAME:
     from:
      secret: kibana-secrets
      key: ELASTICSEARCH_USERNAME
  ELASTICSEARCH_PASSWORD:
     from:
      secret: kibana-secrets
      key: ELASTICSEARCH_PASSWORD
  ELASTICSEARCH_HOSTS:
     from:
      secret: kibana-secrets
      key: ELASTICSEARCH_HOSTS
      
# Uncommit and define your kibana basePath if it's needed
files:
  kibana.yml:
    server.basePath: /kibana
    server.rewriteBasePath: true

plugins:
  enabled: true
  values:
    - logtrail,0.1.31,https://github.com/sivasamyk/logtrail/releases/download/v0.1.31/logtrail-7.9.2-0.1.31.zip

extraConfigMapMounts:
  - name: logtrail-configs
    configMap: logtrail-config
    mountPath: /usr/share/kibana/plugins/logtrail/logtrail.json
    subPath: logtrail.json

service:
  externalPort: 5601
  internalPort: 5601

ingress:
  enabled: true        
  hosts:
    - kibana.my-domain.net 

podAnnotations:
  filebeat_logs: "false"

livenessProbe:
  enabled: false
  path: /kibana/login
  initialDelaySeconds: 60
  timeoutSeconds: 30

readinessProbe:
  enabled: false
  path: /kibana/login
  initialDelaySeconds: 60
  timeoutSeconds: 30
  periodSeconds: 5
```

Finally install it!

```
helm install \
   kibana-test stable/kibana \
   --namespace infrastructure \
   --values kibana.yml
```

### Step #5. Create index patterns in Kibana

Open your Kibana url, go to the Stack Management → Kibana → Index Patterns → Create index pattern

and create your patterns, for example: `namespace1-*`, `namespace2-*`, `namespace3-*`, `namespace4-*`, `nginx-*` and `kube-system-*`

