#!/bin/sh
# 
# The script can be used to quickly deploy and configure a Wallarm WAF node on a supported Linux OS.
#

# The name of the script - used for tagging of syslog messages
TAG="getwallarm.sh"

# Log a message to the console and syslog.
log_message() {
	SEVERITY=$1
	MESSAGE=$2
	echo "$(date):" "$SEVERITY" "$MESSAGE"
	logger -t "$TAG" "$SEVERITY" "$MESSAGE"
}

usage() {
	echo "Usage: 

	Supported parameters (all the parameters are optional):
		-h
			This help message.
		-S <SITE_NAME>
			The name of used Wallarm site: EU or US1 (by default the script uses EU site).
		-u <DEPLOY_USER>
			The username to be used for the new node registration process.
		-p <DEPLOY_PASSWORD>
			The password to be used for the new node registration process.
		-n <NODE_MAME>
			The name of the node as it will visible in the Wallarm console UI (by 
			default the script will use the host name).
		-d <DOMAIN_NAME>
			The WAF reverse proxy will be configured to handle traffic for the domain.
		-o <ORIGIN_SERVER>
			The WAF reverse proxy will be configured to send upstream requests to the
			specified IP address or domain name."
}

check_if_root() {
	log_message INFO "Checking whether the script runs as root..."
	if [ "$(id -u)" -ne 0 ]; then
		log_message ERROR "This script must be executed with root permissions" 
		exit 1
	fi
}

disable_selinux() {
        log_message INFO "Checking whether SELinux is installed (and disabling it if it installed)..."
	SELINUXENABLED=$(which selinuxenabled)
	SETENFORCE=$(which setenforce)
        if [ -z "$SELINUXENABLED" ]; then
                log_message INFO "Cannot find 'selinuxenabled' binary - it looks like SELinux is not installed on the server."
                return
        fi

        if [ -z "$SETENFORCE" ]; then
                log_message WARNING "Cannot find 'setenforce' tool - will not try to disabled SELinux..."
                return
        fi

        log_message INFO "Running 'setenforce' command to temporary disable SELinux..."
        setenforce 0

        SELINUX_CONF=/etc/selinux/config
        if [ -f "$SELINUX_CONF" ]; then
                log_message INFO "Updating file $SELINUX_CONF to permanently disable SELinux..."
                if ! sed -i 's/enforcing/disabled/g' $SELINUX_CONF; then
			log_message CRTICAL "Failed to update file $SELINUX_CONF and disabled SELinux - aborting"
			exit 1
		fi
		
        fi
}

get_distro() {
	log_message INFO "Discovering the used operating system..." 
	lsb_dist=""
	osrelease=""
	pretty_name=""
	basearch=""

	# Every system that we support has /etc/os-release or not?
	if [ -r /etc/os-release ]; then
		lsb_dist="$(. /etc/os-release && echo "$ID")"
		osrelease="$(. /etc/os-release && echo "$VERSION_ID")"
		if [ "$osrelease" = "8" ]; then
			pretty_name="jessie"
		elif [ "$osrelease" = 9 ]; then
			pretty_name="stretch"
		elif [ "$osrelease" = 10 ]; then
			pretty_name="buster"
		elif [ "$osrelease" = 14.04 ]; then
			pretty_name="trusty"
		elif [ "$osrelease" = 16.04 ]; then
			pretty_name="xenial"
		elif [ "$osrelease" = 18.04 ]; then
			pretty_name="bionic"
		elif [ "$osrelease" = 7 ]; then
			pretty_name="centos"
			lsb_dist="$( rpm -qa \centos-release | cut -d"-" -f1 )"
			osrelease="$( rpm -qa \centos-release | cut -d"-" -f3 )"
			basearch=$(rpm -q --qf "%{arch}" -f /etc/$distro)
		else
			log_message ERROR "It looks like Wallarm does not support your OS. Detected OS details: osrelease = \"$osrelease\""
			exit 1
		fi

	elif [ -r /etc/centos-release ]; then
		lsb_dist="$( rpm -qa \centos-release | cut -d"-" -f1 )"
		osrelease="$( rpm -qa \centos-release | cut -d"-" -f3 )"
		basearch=$(rpm -q --qf "%{arch}" -f /etc/$distro)
	else
		log_message ERROR "It looks like Wallarm does not support your OS. Detected OS details: osrelease = \"$osrelease\""
		exit 1
	fi 


	log_message INFO "Detected OS details: lsb_dist=$lsb_dist, osrelease=$osrelease, pretty_name=$pretty_name, basearch=$basearch"
}

#install 
do_install() {

	#do some platform detection
	get_distro

	#install nginx    

	case $lsb_dist in
		debian|ubuntu)
			log_message INFO "Configuring official Nginx repository key..."
			apt-get update && apt-get install wget apt-transport-https dirmngr -y
			KEY_FILE=nginx_signing.key
			wget -O "$KEY_FILE" "https://nginx.org/keys/$KEY_FILE"
			if [ ! -s "$KEY_FILE" ]; then
				log_message CRITICAL "Failed to download file $KEY_FILE - aborting..."
				exit 1
			fi
			if ! apt-key add "$KEY_FILE"; then
				log_message CRITICAL "apt-key failed to add file $KEY_FILE - aborting..."
				exit 1
			fi

			log_message INFO "Configuring official Nginx repository..."
			sh -c "echo 'deb https://nginx.org/packages/$lsb_dist/ $pretty_name nginx'\
				> /etc/apt/sources.list.d/nginx.list"
			sh -c "echo 'deb-src https://nginx.org/packages/$lsb_dist/ $pretty_name nginx'\
				>> /etc/apt/sources.list.d/nginx.list"

			log_message INFO "Removing nginx-common package..." 
			apt-get remove nginx-common

			log_message INFO "Installing official Nginx package..."
			apt-get update
			if ! apt-get install -y nginx; then
				log_message CRITICAL "Failed to install package nginx - aborting"
				exit 1
			fi

			log_message INFO "Adding Wallarm repository key..."
                        for i in 1 2 3 4 5; do
                                apt-key adv --keyserver keys.gnupg.net --recv-keys 72B865FD && break || sleep 2;
                                log_message WARNING "Retrying - attempt $i of 5..."
                        done

			log_message INFO "Configuring Wallarm repository..."
			sh -c "echo 'deb http://repo.wallarm.com/$lsb_dist/wallarm-node\
				$pretty_name/'\
				>/etc/apt/sources.list.d/wallarm.list"
			apt-get update

			log_message INFO "Installing Wallarm packages..."
			if ! apt-get install -y --no-install-recommends wallarm-node nginx-module-wallarm; then
				log_message CRITICAL "Failed to install Wallarm WAF node packages - aborting."
				exit 1
			fi

			;;
		centos)
			log_message INFO "Configuring official Nginx repository..."
			echo "[nginx]" > /etc/yum.repos.d/nginx.repo
			echo "name=nginx repo" >> /etc/yum.repos.d/nginx.repo
			echo "baseurl=https://nginx.org/packages/centos/$osrelease/$basearch/" >> /etc/yum.repos.d/nginx.repo
			echo "gpgcheck=0" >> /etc/yum.repos.d/nginx.repo
			echo "enabled=1" >> /etc/yum.repos.d/nginx.repo

			log_message INFO "Installing official Nginx packages..."
			yum update -y
			if ! rpm --quiet -q nginx; then
				if ! yum install nginx -y; then
					log_message CRITICAL "Failed to install package nginx - aborting."
					exit 1
				fi
			fi

			log_message INFO "Configuring Wallarm repository..."
			case $osrelease in
				6)
					if ! rpm --quiet -q epel-release; then
						yum install --enablerepo=extras -y epel-release centos-release-SCL
					fi
					if ! rpm --quiet -q wallarm-node-repo; then
						rpm -i https://repo.wallarm.com/centos/wallarm-node/6/2.14/x86_64/Packages/wallarm-node-repo-1-4.el6.noarch.rpm
					fi
					;;
				7)
					if ! rpm --quiet -q epel-release; then
						yum install -y epel-release
					fi
					if ! rpm --quiet -q wallarm-node-repo; then
						rpm -i https://repo.wallarm.com/centos/wallarm-node/7/2.14/x86_64/Packages/wallarm-node-repo-1-4.el7.noarch.rpm
					fi
					;;
			esac

			log_message INFO "Installing Wallarm packages..."
			yum update -y
			if ! rpm --quiet -q wallarm-node; then
				if ! yum install -y wallarm-node nginx-module-wallarm; then
					log_message CRITICAL "Failed to install Wallarm WAF node packages - aborting."
					exit 1
				fi
			fi

			;;
	esac

	NGINX_CONF=/etc/nginx/nginx.conf
	log_message INFO "Checking whether $NGINX_CONF is already configured to load the Wallarm module..."

	if grep -q ngx_http_wallarm_module.so $NGINX_CONF; then
		log_message INFO "It looks like the file is already configured to load the module."
	else
		log_message INFO "Updating $NGINX_CONF to load Wallarm Nginx module..."
		sed -i '/worker_processes.*/a load_module modules/ngx_http_wallarm_module.so;' /etc/nginx/nginx.conf
	fi

	CONF_DIR=/etc/nginx/conf.d/
	if [ -f $CONF_DIR/wallarm.conf -o -f $CONF_DIR/wallarm-status.conf ]; then
		log_message INFO "It looks like default Wallarm configuration files alredy present in $CONF_DIR directory."
	else
		log_message INFO "Copying default Wallarm configuration files to $CONF_DIR directory..."
		cp /usr/share/doc/nginx-module-wallarm/examples/*.conf $CONF_DIR
	fi

	log_message INFO "Enabling Nginx to launch automatically during the server startup sequence..."
	systemctl enable nginx
}

# 
# Add the node the the cloud
#
add_node() {
	log_message INFO "Working on connecting the node to the Wallarm cloud..."

	NODE_CONF=/etc/wallarm/node.yaml

	if [ -z "$API_USERNAME" ]; then
		log_message INFO "Wallarm API credentials are specified as -u and -p parameters of the script - skipping the node provisioning step."
		return
	fi

	ADDNODE_SCRIPT=/usr/share/wallarm-common/addnode
	if [ ! -x $ADDNODE_SCRIPT ]; then
		log_message ERROR "Expected script $ADDNODE_SCRIPT is not present - something is wrong with Wallarm packages - aborting."
       		exit 1
	fi

	log_message INFO "Running $ADDNODE_SCRIPT script to add the new to the Wallarm cloud (API endpoint $API_HOST)..."
 	if ! $ADDNODE_SCRIPT --force -H "$API_HOST" --username "$API_USERNAME" --password "$API_PASSWORD" --name "$MY_NODE_NAME"; then
		log_message CRITICAL "Failed to register the node in Wallarm Cloud - aborting..."
		exit 1
	fi
	if [ ! -s "$NODE_CONF" ]; then
		log_message CRITICAL "Node configuration $NODE_CONF is empty or does not exist - aborting."
		exit 1
	fi 

	echo "sync_blacklist:" >> "$NODE_CONF"
    	echo "  nginx_url: http://127.0.0.9/wallarm-acl" >> "$NODE_CONF"

	NGINX_CRON_FILE=/etc/cron.d/wallarm-node-nginx
	log_message INFO  "Updating $NGINX_CRON_FILE to enabled the syncing of black lists..."

	if ! sed -i -Ee 's/^#(.*sync-blacklist.*)/\1/' $NGINX_CRON_FILE; then
		log_message CRITICAL "Failed to update file $NGINX_CRON_FILE - aborting."
		exit 1
	fi
}

#
# Configure the Nginx to handle the specified domain in reverse proxy mode
#
configure_proxy() {
	log_message INFO "Checking whether we need to configure the Nginx proxy..."
	CONF_FILE=/etc/nginx/conf.d/wallarm-proxy.conf	

	if [ -z "$DOMAIN_NAME" ]; then
		log_message INFO "Script parameter -d is not specified - skipping the proxy configuration step..."
		return
	fi

	if [ -z "$ORIGIN_NAME" ]; then
		log_message INFO "Origin address is not specified (script option -o) - using domain name $DOMAIN_NAME"
		ORIGIN_NAME=$DOMAIN_NAME
	fi

	log_message INFO "Creating Nginx configuration file $CONF_FILE with settings for domain $DOMAIN_NAME and origin address $ORIGIN_NAME..."

cat > $CONF_FILE << EOF

# Set global Wallarm WAF mode to "block"
wallarm_mode block;

map \$remote_addr \$wallarm_mode_real {
  default block;
  include /etc/nginx/scanner-ip-list;
}

server {

  listen       80;
  # the domains for which traffic is processed
  server_name $DOMAIN_NAME;

  # turn on the Wallarm WAF blocking mode
  wallarm_mode \$wallarm_mode_real;
  # wallarm_mode monitoring; 
  # wallarm_instance 1;

  # Configure IP blocking using Wallarm blacklist ACL
  wallarm_acl default;

  location / {
    # setting the address for request forwarding
    proxy_pass http://$ORIGIN_NAME;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}

EOF

	CONF_FILE2=/etc/nginx/conf.d/wallarm-acl.conf
	log_message INFO "Creating Nginx configuration file $CONF_FILE2..."
cat > $CONF_FILE2 << EOF
wallarm_acl_db default {
    wallarm_acl_path /var/cache/nginx/wallarm_acl_default;
    wallarm_acl_mapsize 64m;
}

server {
    listen 127.0.0.9:80;

    server_name localhost;

    allow 127.0.0.0/8;
    deny all;

    access_log off;

    location /wallarm-acl {
        wallarm_acl default;
        wallarm_acl_api on;
    }
}

EOF

	SCANNER_IPS=/etc/nginx/scanner-ip-list
	log_message INFO "Creating file $SCANNER_IPS with a list of Wallarm scanner IPs..."
cat > $SCANNER_IPS << EOF
# US scanners 
23.239.18.250 off;
104.237.155.105 off;
45.56.71.221 off;
45.79.194.128 off;
104.237.151.202 off;
45.33.15.249 off;
45.33.43.225 off;
45.79.10.15 off;
45.33.79.18 off;
45.79.75.59 off;
23.239.30.236 off;
50.116.11.251 off;
45.56.123.144 off;
45.79.143.18 off;
172.104.21.210 off;
74.207.237.202 off;
45.79.186.159 off;
45.79.216.187 off;
45.33.16.32 off;
96.126.127.23 off;
172.104.208.113 off;
192.81.135.28 off;
35.236.51.79 off;
35.236.75.97 off;
35.236.111.124 off;
35.236.108.88 off;
35.236.16.246 off;
35.236.61.185 off;
35.236.110.91 off;
35.236.14.198 off;
35.235.124.137 off;
35.236.48.47 off;
35.236.100.176 off;
35.236.18.117 off;
35.235.112.188 off;
35.236.55.214 off;
35.236.126.84 off;
35.236.3.158 off;
35.236.127.211 off;
35.236.118.146 off;
35.236.20.89 off;
35.236.1.4 off;

# EU scanners 
139.162.130.66 off;
139.162.144.202 off;
139.162.151.10 off;
139.162.151.155 off;
139.162.156.102 off;
139.162.157.131 off;
139.162.158.79 off;
139.162.159.137 off;
139.162.159.244 off;
139.162.163.61 off;
139.162.164.41 off;
139.162.166.202 off;
139.162.167.19 off;
139.162.167.51 off;
139.162.168.17 off;
139.162.170.84 off;
139.162.171.141 off;
139.162.172.35 off;
139.162.174.220 off;
139.162.174.26 off;
139.162.175.71 off;
139.162.176.169 off;
139.162.178.148 off;
139.162.179.214 off;
139.162.180.37 off;
139.162.182.156 off;
139.162.182.20 off;
139.162.184.225 off;
139.162.185.243 off;
139.162.186.136 off;
139.162.187.138 off;
139.162.188.246 off;
139.162.190.22 off;
139.162.190.86 off;
139.162.191.89 off;
85.90.246.120 off;
104.200.29.36 off;
104.237.151.23 off;
173.230.130.253 off;
173.230.138.206 off;
173.230.156.200 off;
173.230.158.207 off;
173.255.192.83 off;
173.255.193.92 off;
173.255.200.80 off;
173.255.214.180 off;
192.155.82.205 off;
23.239.11.21 off;
23.92.18.13 off;
23.92.30.204 off;
45.33.105.35 off;
45.33.33.19 off;
45.33.41.31 off;
45.33.64.71 off;
45.33.65.37 off;
45.33.72.81 off;
45.33.73.43 off;
45.33.80.65 off;
45.33.81.109 off;
45.33.88.42 off;
45.33.97.86 off;
45.33.98.89 off;
45.56.102.9 off;
45.56.104.7 off;
45.56.113.41 off;
45.56.114.24 off;
45.56.119.39 off;
50.116.35.43 off;
50.116.42.181 off;
50.116.43.110 off;
66.175.222.237 off;
66.228.58.101 off;
69.164.202.55 off;
72.14.181.105 off;
72.14.184.100 off;
72.14.191.76 off;
172.104.150.243 off;
139.162.190.165 off;
139.162.130.123 off;
139.162.132.87 off;
139.162.145.238 off;
139.162.146.245 off;
139.162.162.71 off;
139.162.171.208 off;
139.162.184.33 off;
139.162.186.129 off;
172.104.128.103 off;
172.104.128.67 off;
172.104.139.37 off;
172.104.146.90 off;
172.104.151.59 off;
172.104.152.244 off;
172.104.152.96 off;
172.104.154.128 off;
172.104.229.59 off;
172.104.250.27 off;
172.104.252.112 off;
45.33.115.7 off;
45.56.69.211 off;
45.79.16.240 off;
50.116.23.110 off;
85.90.246.49 off;
172.104.139.18 off;
172.104.152.28 off;
139.162.177.83 off;
172.104.240.115 off;
172.105.64.135 off;
139.162.153.16 off;
172.104.241.162 off;
139.162.167.48 off;
172.104.233.100 off;
172.104.157.26 off;
172.105.65.182 off;
178.32.42.221 off;
46.105.75.84 off;
51.254.85.145 off;
188.165.30.182 off;
188.165.136.41 off;
188.165.137.10 off;
54.36.135.252 off;
54.36.135.253 off;
54.36.135.254 off;
54.36.135.255 off;
54.36.131.128 off;
54.36.131.129 off;

EOF

	log_message INFO "Creating Nginx cache directory /var/cache/nginx/wallarm_acl_default..."
	mkdir -p /var/cache/nginx/wallarm_acl_default
	chown nginx /var/cache/nginx/wallarm_acl_default

	log_message INFO "Using 'nginx -t' command verifying that the Nginx configuration is correct..."
	if ! nginx -t; then
		log_message ERROR "It looks like Nginx doesn't like the new configuration - aborting."
		exit 1
	fi

        log_message INFO "Starting the Nginx service (just in case if it is not running)..."
        service nginx start

	log_message INFO "Reloading Nginx configuration..."
	service nginx reload

}

#
# Send a few test requests
#
test_proxy() {
	log_message INFO "Sending a request to Wallarm WAF status page http://127.0.0.8/wallarm-status..."
	curl http://127.0.0.8/wallarm-status

	if [ -z "$DOMAIN_NAME" ]; then
		log_message INFO "The domain name is not specified - skipping the domain testing step..."
		return
	fi
	log_message INFO "Sending a regular HTTP request to the localhost for domain $DOMAIN_NAME..."
	curl -v -H "Host: $DOMAIN_NAME" http://localhost/ > /dev/null

	log_message INFO "Sending a malicious HTTP request to the localhost for domain $DOMAIN_NAME (the response code should be 403)..."
	curl -v -H "Host: $DOMAIN_NAME" "http://localhost/?id='or+1=1--a-<script>prompt(1)</script>" > /dev/null
}

# By default use the Wallarm EU site
API_SITE=eu

MY_NODE_NAME=`hostname`

while getopts :hu:p:d:o:n:S: option
do
	case "$option" in
		h)
			usage;
			exit 1
			;;
		u)
			# Wallarm username for WAF node registration
			API_USERNAME=$OPTARG;
			;;
		p)
			# Wallarm password for WAF node registration
			API_PASSWORD=$OPTARG;
			;;
		n)
			# The name of the node
			MY_NODE_NAME=$OPTARG;
			;;
		d)
			# Domain name as recognized by this node and the origin server
			DOMAIN_NAME=$OPTARG;
			;;
		o)
			# IP address or DNS name of the origin server
			ORIGIN_NAME=$OPTARG;
			;;
		S)	
			# API site name (EU or US1)
			API_SITE=`echo $OPTARG | tr '[:upper:]' '[:lower:]'`;
			;;
		*)
			echo "Hmm, an invalid option was received."
			usage
			exit 1
			;;
	esac
done

if [ ! -z "$API_USERNAME" -a -z "$API_PASSWORD" ]; then
	log_message ERROR "Please specify both username and password parameters."
	usage
	exit 1
fi

if [ "$API_SITE" = "us1" ]; then
	API_HOST=us1.api.wallarm.com
elif [ "$API_SITE" = "eu" ]; then
	API_HOST=api.wallarm.com
else
	log_message ERROR "Unknown Wallarm site name \"$API_SITE\". Accepted Wallarm site names are EU and US1. Aborting."
	usage
	exit 1
fi

check_if_root

disable_selinux

do_install

add_node

configure_proxy

test_proxy

log_message INFO "We've completed the Wallarm WAF node deployment process."
