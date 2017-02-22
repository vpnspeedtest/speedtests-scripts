#!/usr/bin/python
import subprocess, netifaces, telnetlib, re, string, sys, select,getopt, signal, socket, time, datetime, os, json, zipfile, pysftp, random
from time import sleep

DEFAULT_HTTPS_URL = "https://dl.google.com/dl/android/studio/ide-zips/2.2.2.0/android-studio-ide-145.3360264-linux.zip"
DEFAULT_TORRENT_URL = "http://releases.ubuntu.com/16.10/ubuntu-16.10-desktop-amd64.iso.torrent"
TORRENT_TIMEOUT = "60"  #seconds of inactivity
OPENVPN_MGMT_PORT = "5555"
VPN_CONNECT_TIMEOUT = 199    #seconds
MAX_TLS_TIMEOUTS = 3
MAX_DNS_TESTS = 10
LOG_DIR = "logs/"
UNKNOWN_VPN = "Unknown"
CONFIG_FILE_DNS = "vpnspeedtest-dns.json"
CONFIG_FILE_VPNS = "vpnspeedtest-vpns.json"

VULTR_STARTUP_LOG = "/tmp/firstboot.log"
VULTR_METADATA_URL = "http://169.254.169.254/v1.json"
VULTR_REGIONS = {
                "CDG":"Paris",
                "NRT":"Tokyo",
                "MIA":"Miami",
                "SJC":"Silicon Valley",
                "SYD":"Sydney",
                "SGP":"Singapore",
                "EWR":"New Jersey",
                "DFW":"Dallas",
                "ORD":"Chicago",
                "LAX":"Los Angeles",
                "SEA":"Seattle",
                "AMS":"Amsterdam",
                "ATL":"Atlanta",
                "FRA":"Frankfurt",
                "LHR":"London"
                }
                

def main(argv):

    vpn_services_map = {}
      
    #load info on VPn providers configs
    if os.path.isfile(CONFIG_FILE_VPNS):
        try:
            with open(CONFIG_FILE_VPNS) as config_file:    
                vpn_services_map = json.load(config_file)
                #print "Number of VPN providers configured in file " + CONFIG_FILE_VPNS + " is: ", len(vpn_services_map)
        except ValueError as e:
            print "Error with the VPN config file: " + CONFIG_FILE_VPNS
            print str(e)
            exit()
    else:
        print "Could not find the VPN config file: " + CONFIG_FILE_VPNS
        #exit()
    
    helptext_vpns = ','.join(vpn_services_map.keys())    
    helptext = """vpnspeedtest.py 
            --config            Name (and path) of the OpenVPN config file to connect with.
                                If the OpenVPN config file contains "auth_user_pass" then
                                you will need to enter your VPN username and password during the test.
                                (or supply them with --vpn_username= and --vpn_password=)
                OR
            --vpn               The same as --vpn-list but to only test one VPN provider.
                OR
            --vpn-list          Name(s) of the VPN service(s) to test (comma separated list).
                                Each VPN service needs to be defined in the file: vpnspeedtest-vpns.json
                                If this option is supplied then the OpenVPN files from the vpn_configs/ folder will be used.
                                You need to create auth files containing the VPN username and password in the vpn_auth/ folder.
                                Use the name of the VPN service (lowercase) with a .txt extension (eg: testvpn.txt)
                                with the username on line #1 and password on line #2
            
            --auth-username     VPN username (only if one VPN service is being tested)  [optional]
            --auth-password     VPN password (only if one VPN service is being tested)  [optional]

            --sftp-host         Domain or IP address of the SFTP server to send logs and results to [optional]
            --sftp-username     SFTP username   [optional]
            --sftp-password     SFTP password   [optional]

            Examples:
            python vpnspeedtest.py --config myFolder/MyVPNConfig.ovpn (and enter VPN username & password later)
                OR
            python vpnspeedtest.py --vpn=testvpn --auth-username=vpnuser777 --auth-password=secret
                OR
            python vpnspeedtest.py --vpn-list=examplevpn,testvpn,myvpn
            
            """
    helptext += "Availabe VPNs for --vpn= and --vpn-list=" + helptext_vpns + "\n"
            
            
    dns_lookup_list = []
    vpn_config_file = ''
    vpn_providers = ''
    test_location = ''
    test_id = ''
    torrent_url = ''
    https_url = ''
    auth_username = ''
    auth_password = ''
    #auth_zip_url = ''
    sftp_host = ''
    sftp_username = ''
    sftp_password = ''
    
    #load list of DNS entries to check
    if os.path.isfile(CONFIG_FILE_DNS):
        try:
            with open(CONFIG_FILE_DNS) as config_file:    
                dns_lookup_list = json.load(config_file)
                #print "Number of DNS entries to test:", len(dns_lookup_list)
        except ValueError as e:
            print "Error with the DNS config file: " + CONFIG_FILE_DNS
            print str(e)
            exit()
    else:
        print "Could not find the DNS config file: " + CONFIG_FILE_DNS
        exit()
    
    #download the Vultr metadata to determine server location
    try:
        vultr_metadata_req = ['curl', '-s', VULTR_METADATA_URL]
        vultr_metadata_str = subprocess.check_output(vultr_metadata_req)
        vultr_metadata = json.loads(vultr_metadata_str)	
    except subprocess.CalledProcessError as e:
        print "curl error:", str(e)
        print "Are you running this on a Vultr server?"
        exit()
    else:
        test_id = vultr_metadata['instanceid']
        if not test_location:
            vultr_region_code = vultr_metadata['region']['regioncode']
            test_location = VULTR_REGIONS[vultr_region_code]
        print "Testing from " + test_location + " with testID:", test_id

    try:
        opts, args = getopt.getopt(argv,"",["help", "config=", "vpn=", "vpn-list=", "auth-username=", "auth-password=", "torrent-url=", "https-url=", "sftp-host=", "sftp-username=", "sftp-password="])
    except getopt.GetoptError:
        print "Options error!"
        print(helptext)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("--help"):
            print(helptext)
            sys.exit(2)
        elif opt in ("--config"):
            vpn_config_file = arg
        elif opt in ("--vpn-list") or opt in ("--vpn"):
            vpn_providers = arg.lower()
        elif opt in ("--auth-username"):
            auth_username = arg
        elif opt in ("--auth-password"):
            auth_password = arg
        elif opt in ("--torrent-url"):
            torrent_url = arg
        elif opt in ("--https-url"):
            https_url = arg
        elif opt in ("--sftp-host"):
            sftp_host = arg
        elif opt in ("--sftp-username"):
            sftp_username = arg
        elif opt in ("--sftp-password"):
            sftp_password = arg

    if not vpn_providers and not vpn_config_file:
        print("You need to specify at least one VPN service name in --vpn-list=myvpn or one OpenVPN config file with --config=MyFile.ovpn")
        print(helptext)
        exit()
        
    #if user has specified an openvpn config file with --config
    if vpn_config_file:
        if not os.path.isfile(vpn_config_file):
            print "OpenVPN config file specified with --config not found: " + vpn_config_file
            exit()
        else:
            "Setting up unknown VPN"
            unknown_vpn = UNKNOWN_VPN
            vpn_providers = unknown_vpn
            vpn_test_locations = {test_location:[vpn_config_file]}  #later on we expect a list of filenames for this location
            vpn_services_map[unknown_vpn] = vpn_test_locations      #store the openvpn filename for this unknown vpn
            
                
    if not torrent_url:
        print "--torrent-url was not specified. Using the default speedtest torrent URL: " + DEFAULT_TORRENT_URL
        torrent_url = DEFAULT_TORRENT_URL

    if not https_url:
        print "--https-url was not specified. Using the default speedtest HTTPS URL: " + DEFAULT_HTTPS_URL
        https_url = DEFAULT_HTTPS_URL

    if auth_username and not auth_password:
        print "You supplied auth-username but you need to specify auth_password too."
        print(helptext)
        sys.exit(2)
        
    if not auth_username and auth_password:
        print "You supplied auth-password but you need to specify auth-username too."
        print(helptext)
        sys.exit(2)
        
    if sftp_host:
        if not sftp_username:
            print "You supplied sftp-host but you need to specify sftp-username and sftp-password too."
            print(helptext)
            sys.exit(2)
        if not sftp_password:
            print "You supplied sftp-host and sftp-username but you need to specify sftp-password too."
            print(helptext)
            sys.exit(2)
    
            
    vpn_providers_list = vpn_providers.split(',')
    if vpn_providers_list and not vpn_config_file:
        #create auth file if only one vpn is being tested
        if len(vpn_providers_list) > 1 and auth_username:
            print "You can only use auth-username and auth-password if you are testing one VPN service."
            print(helptext)
            sys.exit(2)
    
        #create the auth file
        if len(vpn_providers_list) == 1 and auth_username and auth_password:
            vpn_provider = vpn_providers_list[0]
            auth_file = open('vpn_auth/'+vpn_provider+'.txt', 'w')
            auth_file.write(auth_username + '\n')
            auth_file.write(auth_password + '\n')
            auth_file.close()
    
        #check that the vpn service has configs and an auth file for this location
        for vpn_provider in vpn_providers_list:
            if vpn_provider not in vpn_services_map:
                print vpn_provider + " is not supported (yet)"
                continue
                #exit()
        
            vpn_test_locations = vpn_services_map[vpn_provider]
            if test_location not in vpn_test_locations:
                print "OpenVPN config files not defined for VPN service " + vpn_provider + " and location " + test_location
                print "Supported locations for " + vpn_provider + " are:"
                for location in vpn_test_locations:
                    print location
                #exit()
            
            vpn_auth_file = "vpn_auth/"+vpn_provider+".txt"
            if not os.path.isfile(vpn_auth_file):
                print "No username/password file found for " + vpn_provider
                print "Please create vpn_auth/"+vpn_provider+".txt with the vpn username on line #1 and the vpn password on line #2"
                #exit()

    #download the torrent file we'll use for testing
    try:
        print "Downloading the torrent file from: " + torrent_url
        #download_torrent_info = torrent_url.split('/')
        #torrent_filename = download_torrent_info[-1]
        torrent_filename = 'vpnspeedtest.torrent'
        download_torrent = ['curl', '-s', '-o', 'torrents/'+torrent_filename, torrent_url]
        download_torrent_result = subprocess.check_output(download_torrent)	
    except subprocess.CalledProcessError as e:
        print "curl error:", str(e)
        exit()
    else:
        print "Downloaded torrent file OK"

    
    log_to_terminal = True
    if (len(vpn_providers_list) > 1):
        log_to_terminal = False
        print "Since more than 1 VPN is being tested the logging will be redirected to log files instead of the terminal."
    
    speed_test_results = []
    try:
        #for vpn_provider in vpn_providers_list:
        while vpn_providers_list:
            
            vpn_provider = vpn_providers_list.pop(random.randrange(len(vpn_providers_list)))
            print 'Testing VPN service:', vpn_provider
            vpn_test_locations = vpn_services_map[vpn_provider]
            openvpn_filenames = vpn_test_locations[test_location]
            if not openvpn_filenames:
                print "ERROR: No OpenVPN config files configured for " + vpn_provider
                continue

            try:
                speedtest_metadata = testVPN(vpn_provider, test_location, test_id, openvpn_filenames, dns_lookup_list, https_url, torrent_filename, torrent_url, log_to_terminal)
                speedtest_metadata["timestamp-end-iso"] = datetime.datetime.utcnow().isoformat("T") + "Z" #RFC3339 UTC
                speed_test_results.append(speedtest_metadata)
                
                sys.stdout = sys.__stdout__     #restore stdout - since testVPN() redirects them to log files

                #write all speedtest metadata to json file
                with open(LOG_DIR+speedtest_metadata["log-results"], 'w') as json_results:
                    json.dump(speedtest_metadata, json_results, indent=4, sort_keys=True)
            except KeyboardInterrupt:
                raise
            except:
                e = sys.exc_info()[0]
                print "Fatal error while testing " + vpn_provider + " was: " + str(e)
        
            try:
                if sftp_host and sftp_username and sftp_password:
                    print "sending test result via SFTP"
                    cnopts = pysftp.CnOpts()
                    cnopts.hostkeys = None
                    with pysftp.Connection(sftp_host, username=sftp_username, password=sftp_password, cnopts=cnopts) as sftp:
                        if os.path.isfile(LOG_DIR+speedtest_metadata['log-bittorrent']):
                            sftp.put(LOG_DIR+speedtest_metadata['log-bittorrent'], preserve_mtime=True)
                        if os.path.isfile(LOG_DIR+speedtest_metadata['log-openvpn']):
                            sftp.put(LOG_DIR+speedtest_metadata['log-openvpn'], preserve_mtime=True)
                        if os.path.isfile(LOG_DIR+speedtest_metadata['log-results']):
                            sftp.put(LOG_DIR+speedtest_metadata['log-results'], preserve_mtime=True)
                        if os.path.isfile(LOG_DIR+speedtest_metadata['log-speedtest']):
                            sftp.put(LOG_DIR+speedtest_metadata['log-speedtest'], preserve_mtime=True)
                            
                        #send OK file to indicate we're done sending log files for this result
                        OK_filename = LOG_DIR+speedtest_metadata['log-results']+'.OK'
                        f = open(OK_filename,'w')
                        f.write('OK')
                        f.close()
                        sftp.put(OK_filename, preserve_mtime=True)
                        sftp.close()
            except KeyboardInterrupt:
                raise
            except IOError as e:
                print "Error while sending logs for " + vpn_provider + " was: " + str(e)
            except:
                e = sys.exc_info()[0]
                print "Error while sending logs for " + vpn_provider + " was: " + str(e)
    except KeyboardInterrupt:
        print 'KeyboardInterrupt caught'
        disconnectVPN()
    
    results_json = json.dumps(speed_test_results, indent=4, sort_keys=True)
    print "Speed test results are:\n", results_json
    results_filename = LOG_DIR+test_id+'.json'
    results_file = open(results_filename, 'w')
    results_file.write(results_json)
    results_file.close()
     
    
    if sftp_host and sftp_username and sftp_password:
        print "sending server done message via SFTP"
        cnopts = pysftp.CnOpts(knownhosts=None)
        cnopts.hostkeys = None
        with pysftp.Connection(sftp_host, username=sftp_username, password=sftp_password, cnopts=cnopts) as sftp:
            #send the .json results which indicates test is finished
            sftp.put(results_filename, preserve_mtime=True)
            if os.path.isfile(VULTR_STARTUP_LOG):
                sftp.put(VULTR_STARTUP_LOG, remotepath=test_id+'.log', preserve_mtime=True)
            sftp.close()
    
    print "Done!"
    exit()

def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    disconnectVPN()
    sys.exit(0)

def disconnectVPN():    
    try:
        tn = telnetlib.Telnet('127.0.0.1', OPENVPN_MGMT_PORT)
    except socket.error as e:
        pass
    else:
        tn.read_until("INFO:")
        tn.write("signal SIGTERM\n")
        tn.read_all()
    
def connectVPN(vpn_provider, vpn_config_filename, vpn_auth_filename, vpn_log_filename):
    openvpn_cmd = ['openvpn', 
                    '--management', '127.0.0.1', OPENVPN_MGMT_PORT,
                    '--route-noexec', 
                    #'--auth-user-pass', vpn_auth_filename,
                    '--log', vpn_log_filename,
                    '--script-security', '2',
                    '--up', 'scripts/vpn-up.sh',
                    '--down', 'scripts/vpn-down.sh',
                    '--config', vpn_config_filename]
    if vpn_auth_filename:
        openvpn_cmd.append('--auth-user-pass')
        openvpn_cmd.append(vpn_auth_filename)
        
    openvpn = subprocess.Popen(openvpn_cmd,stderr=subprocess.PIPE)
    
    #See if process died or exited
    if (openvpn.poll() is not None):
        raise ValueError(openvpn.poll())
    
    #use select.poll todo non blocking polling on the openvpn logfile, nohup,out
    tail = subprocess.Popen(['tail','-Fn1',vpn_log_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(tail.stdout)

    #Start polling file
    connected = False
    tls_timeout_count = 0
    cutoff_time = time.time() + VPN_CONNECT_TIMEOUT
    while True:
        if time.time() > cutoff_time:
            print "Timed out trying to connect after " + str(VPN_CONNECT_TIMEOUT) + " seconds."
            p.unregister(tail.stdout)
            tail.terminate()
            raise ValueError(line)
            
        if (connected):
            break
            
        #poll and lock the file 
        if (p.poll(1)):
            #get the stripped stdout
            line = tail.stdout.readline().rstrip()
            if 'TLS handshake failed' in line or 'Connection timed out' in line:
                tls_timeout_count += 1
                if tls_timeout_count == MAX_TLS_TIMEOUTS:
                    print "Reached the maximum number of allowed TLS timeouts: " + str(MAX_TLS_TIMEOUTS)
                    p.unregister(tail.stdout)
                    tail.terminate()
                    raise ValueError(line)
                else:
                    print "TLS Timeout occured - reconnecting..."
            matcherror = re.search(r'SIGTERM|Exit|AUTH_FAILED|--help|Cannot resolve host address', line) 
            if matcherror is not None:
                p.unregister(tail.stdout)
                tail.terminate()
                raise ValueError(line)
            matchsuccess = re.search(r'Completed', line)
            if matchsuccess is not None:
                connected = True

    #unregister the polling 
    p.unregister(tail.stdout)    
    tail.terminate()

    #wait for interface to come up
    tunUp = False
    while True:
        if tunUp:
            break
        for iface in netifaces.interfaces():
            if iface == "tun0":
                tunUp = True    

def testVPN(vpn_provider, test_location, test_id, 
            openvpn_filenames, 
            dns_lookup_list, 
            https_download_url,
            torrent_file, torrent_url, 
            log_to_terminal):
    
    #choose one openvpn config at random
    vpn_config_filename = openvpn_filenames.pop(random.randrange(len(openvpn_filenames)))
    print "Testing VPN server: " + vpn_config_filename
    
    speedtest_metadata = {}
    speedtest_metadata["timestamp-iso"] = datetime.datetime.utcnow().isoformat("T") + "Z" #RFC3339 UTC
    speedtest_metadata["timestamp-nano"] = str(int(time.time() * 1e9))
    speedtest_metadata["vpn-service"] = vpn_provider
    speedtest_metadata["location"] = test_location
    speedtest_metadata["p2p-url"] = torrent_url
    speedtest_metadata["https-url"] = https_download_url

    if UNKNOWN_VPN in vpn_provider:
        speedtest_metadata["vpn-config-file"] = vpn_config_filename
        speedtest_metadata["vpn-auth-file"] = ''
    else:
        speedtest_metadata["vpn-config-file"] = "vpn_configs/"+vpn_provider+"/"+vpn_config_filename
        speedtest_metadata["vpn-auth-file"] = 'vpn_auth/'+vpn_provider+'.txt'
    
    
    #if filename was supplied with --config then remove the path
    tmp_filename = vpn_config_filename.split('/');  
    filename = tmp_filename[-1].replace(".ovpn", "").replace(".conf", "")

    dt = datetime.datetime.utcnow()
    timestamp = dt.strftime("%Y-%m-%d_%H%M%S")    
    speedtest_log_filename_prefix =  test_id + "-" + timestamp + "-" + vpn_provider + "-" + test_location.replace(" ", "") + "-" + filename
    speedtest_metadata["log-openvpn"] = speedtest_log_filename_prefix + "-openvpn.txt"
    speedtest_metadata["log-bittorrent"] = speedtest_log_filename_prefix + "-bittorrent.txt"
    speedtest_metadata["log-speedtest"] = speedtest_log_filename_prefix + "-speedtest.txt"
    speedtest_metadata["log-results"] = speedtest_log_filename_prefix + "-results.json"
    
    #redirect all stdout output to the log file if more than one VPN is being tested
    if (log_to_terminal is False):
        print "Redirecting output to log file: " + LOG_DIR + speedtest_metadata["log-speedtest"]
        sys.stdout = open(LOG_DIR + speedtest_metadata["log-speedtest"], 'w', 0)    #0 = unbuffered

    disconnectVPN() #in case a previous test failed
    print "Connecting to VPN with config file " + speedtest_metadata["vpn-config-file"]
    connect_time_start = datetime.datetime.utcnow()
    try:
        connectVPN(vpn_provider, speedtest_metadata["vpn-config-file"], speedtest_metadata["vpn-auth-file"], LOG_DIR+speedtest_metadata["log-openvpn"])
    except ValueError as e:
        if 'TLS handshake failed' in str(e):
            print "Connection Timeout. See " + LOG_DIR+speedtest_metadata["log-openvpn"] + " for more information."
            disconnectVPN()
            speedtest_metadata["test-result"] = "CONNECTION_TIMEOUT"
            return speedtest_metadata
             
        elif 'AUTH_FAILED' in str(e):
            print "Wrong VPN username or password. Check " + speedtest_metadata["vpn-auth-file"] + " and verify you have the correct details."
            speedtest_metadata["test-result"] = "AUTH_FAILED"
            return speedtest_metadata 
        else:
            print "VPN failed to connect: " + str(e)
            print "See " + LOG_DIR+speedtest_metadata["log-openvpn"] + " for more information."
            disconnectVPN()
            speedtest_metadata["test-result"] = "CONNECTION_FAILED"
            return speedtest_metadata   
        
    connect_time_finish = datetime.datetime.utcnow()
    connect_time_delta = connect_time_finish - connect_time_start
    speedtest_metadata["vpn-connection-time"] = connect_time_delta.total_seconds()
    print "Connected to VPN in " + str(connect_time_delta.total_seconds()) + " seconds"

    
    #test DNS lookup speeds
    dns_lookup_results = []
    while len(dns_lookup_results) < MAX_DNS_TESTS and len(dns_lookup_list) > 0:
        try:
            #choose random URL
            test_url = dns_lookup_list.pop(random.randrange(len(dns_lookup_list)))  
            dns_cmd = ['curl', '--head', '--interface', 'tun0', '--dns-interface', 'tun0', '-w','%{speed_download}\t%{time_namelookup}\t%{time_total}\n', '-o', '/dev/null', '-s', 'http://'+test_url]
            output = subprocess.check_output(dns_cmd)
            speed,dnstime,tottime = output.split()
            if dnstime:
                print "DNS resolve time for " + test_url + " was: " + dnstime
                dns_lookup_results.append(dnstime)
        except subprocess.CalledProcessError as e:
            print "Curl error for " + test_url + " was " + str(e)
            dns_lookup_list = []    #stop testing

    if dns_lookup_results:
        dns_lookup_total = float(0)
        for dns_time in dns_lookup_results:
            dns_lookup_total = dns_lookup_total + float(dns_time)
        dns_average_time = dns_lookup_total / len(dns_lookup_results)
        speedtest_metadata["dns-lookup-time"] = dns_average_time
        print "Average DNS lookup was: " + str(dns_average_time)

    #test speed with bittorrent
    try:
        print "Testing download speed with bittorrent..."
        download_cmd = ['aria2c', 
                        '--interface', 'tun0', 
                        '--log='+LOG_DIR+speedtest_metadata["log-bittorrent"], 
                        '--log-level=notice', 
                        #'--log-level=info', 
                        '--seed-time=0', 
                        '--disable-ipv6=true', 
                        '--bt-max-peers=0',
                        '--bt-stop-timeout='+TORRENT_TIMEOUT, 
                        '--download-result=default', 
                        '--allow-overwrite=true', 
                        '--max-upload-limit=1', 
                        '--summary-interval=0', 
                        '--dir=torrents', 
                        'torrents/'+torrent_file]
        if (log_to_terminal is False):
            ps = subprocess.Popen(download_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            speedtest_log = ps.communicate()[0]
        else:
            speedtest_log = subprocess.check_output(download_cmd)
        print speedtest_log
        if "Stop downloading torrent due to --bt-stop-timeout option" in speedtest_log:
            speedtest_metadata["p2p-download-status"] = 'TIMEOUT'
            speedtest_metadata["p2p-download-speed-Mbps"] = '0'
            print "Download timed out after " + TORRENT_TIMEOUT + " seconds"
        else:
            bittorrentinfo = speedtest_log.split('\n')
            speedtestratio = bittorrentinfo[len(bittorrentinfo) - 11]
            speedtestinfo = bittorrentinfo[len(bittorrentinfo) - 5]
            gid, status, speed, path = speedtestinfo.split('|')
            status = status.strip()
            speed = speed.strip()
            print "Download status is: ", status
            print "Speed was: ", speed
            speed = speed.replace(",","")   #translate 1,013.9 to 1013.9
            if "KiB/s" in speed:
                myspeed = speed.replace("KiB/s", "")
                speed_inmegabits = (float(myspeed) / 1024) * 8
            elif "MiB/s" in speed:
                myspeed = speed.replace("MiB/s", "")
                speed_inmegabits = float(myspeed) * 8

            print "Bittorrent download speed in Mbps:", round(speed_inmegabits, 2)
            speedtest_metadata["p2p-download-speed-Mbps"] = speed_inmegabits
            speedtest_metadata["p2p-download-status"] = 'OK'
    except subprocess.CalledProcessError as e:
        if e.returncode == 7:
            speedtest_metadata["p2p-download-status"] = 'TIMEOUT'
            speedtest_metadata["p2p-download-speed-Mbps"] = '0'
            print "Download timed out after " + TORRENT_TIMEOUT + " seconds"
        else:
            speedtest_metadata["p2p-download-status"] = 'FAILED'
            speedtest_metadata["p2p-download-speed-Mbps"] = '0'
            print "Download error: "+str(e)
    except IndexError as e:
        speedtest_metadata["p2p-download-status"] = 'FAILED'
        speedtest_metadata["p2p-download-speed-Mbps"] = '0'
        print "Download error: "+str(e)
    except ValueError as e:
        speedtest_metadata["p2p-download-status"] = 'FAILED'
        speedtest_metadata["p2p-download-speed-Mbps"] = '0'
        print "Could not translate bittorrent speed to a float: " + str(e)
    
    
    #test speed with https
    try:
        print "Testing download speed with HTTPS..."
        download_cmd = ['curl', '--interface', 'tun0', '--dns-interface', 'tun0', '-w','%{speed_download}\t%{time_namelookup}\t%{time_total}\n', '-o', '/dev/null', https_download_url]
        
        if (log_to_terminal is False):
            ps = subprocess.Popen(download_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            https_speedtest_output = ps.communicate()[0]
            print https_speedtest_output
            
            #handle Vultr network / curl error (exception not thrown)
            if 'curl: (56) SSL read: error' in https_speedtest_output or 'Timeout while contacting DNS servers' in https_speedtest_output:
                speedtest_metadata["test-result"] = "NETWORK_ERROR"
                disconnectVPN()
                return speedtest_metadata
            
            tmp = https_speedtest_output.split('\n')
            speedtest_info = tmp[-2]    #curl adds one blank line at the end so take the 2nd last line
            speed,dnstime,tottime = speedtest_info.split()
        else:
            https_speedtest_output = subprocess.check_output(download_cmd)
            #print "https_speedtest_output:", https_speedtest_output
            speed,dnstime,tottime = https_speedtest_output.split()
        if speed:
            #speed is in Bytes per second. Convert Mega bits per second
            https_speed = ((float(speed) / 1024) / 1024) * 8
            print "HTTPS Download speed in Mbps: " + str(https_speed)
            speedtest_metadata["https-download-speed-Mbps"] = float("{0:.2f}".format(https_speed))
            speedtest_metadata["https-download-status"] = "OK"
    except subprocess.CalledProcessError as e:
            speedtest_metadata["test-result"] = "NETWORK_ERROR"
            disconnectVPN()
            return speedtest_metadata
    
    #test vpn connection is active
    try:
        print "Looking up public IPv4 address..."
        publicip = subprocess.check_output(["curl", "--interface", "tun0", "-s","ipinfo.io/ip"])
        print "Public IPv4 address is: " + publicip
    except subprocess.CalledProcessError as e:
        speedtest_metadata["test-result"] = "NETWORK_ERROR"
        disconnectVPN()
        return speedtest_metadata
    else:
        speedtest_metadata["vpn-public-IP"] = publicip.strip()
    
    #add tun0 data to the end 
    try:
        ifconfig_req = ['ifconfig', 'tun0']
        ifconfig_output = subprocess.check_output(ifconfig_req)
        
        if 'RX bytes:0 (0.0 B)'in ifconfig_output:
            speedtest_metadata["test-result"] = "NETWORK_ERROR"
            disconnectVPN()
            return speedtest_metadata
        
        print ifconfig_output
    except subprocess.CalledProcessError as e:
        speedtest_metadata["test-result"] = "NETWORK_ERROR"
        disconnectVPN()
        return speedtest_metadata


    disconnectVPN()
    speedtest_metadata["test-result"] = "OK"
    
    print "Finished testing " + vpn_provider
    return speedtest_metadata



if __name__ == "__main__":
    main(sys.argv[1:])
