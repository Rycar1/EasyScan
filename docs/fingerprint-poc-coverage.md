# EasyScan 指纹 ↔ POC 覆盖对照表

> 自动生成：对每个 hfinger 指纹名调用 `nucleiprobe.TagsFor` 得到实际下发的 nuclei -tags。
> tags 非空 = 会下发该 tag 给 nuclei；tags 为空 = 仅能识别、被有意跳过（宽泛类别或无对应模板）。
>
> ⚠️ 重要说明：本表「覆盖」只代表 `TagsFor` 会产出一个 tag 并下发给 nuclei，**不代表 nuclei 一定有对应模板**。
> 大量长尾产品（如 `35企业邮箱系统→35`、`53客服→53`）归一化出的 token 在 nuclei 模板库里通常并无匹配，实际会跑 0 条 POC。
> 真正稳定关联到 POC 的是 tags.go 里人工核验过的显式别名产品（Spring/Apache/Nacos/WebLogic/GitLab/致远/泛微/若依 等约 60 项），
> 其余为「产品名恰好等于 nuclei tag」时自动命中。要精确到「有几条模板」需再与本地 nuclei 模板库交叉比对。

## 统计

| 指标 | 数量 |
|---|---|
| 唯一指纹总数 | 860 |
| 可下发 POC（覆盖） | 798 |
| 仅识别 / 被跳过 | 62 |

## 一、可下发 POC 的指纹（覆盖）

| 指纹名 | 类别 | nuclei -tags |
|---|---|---|
| 1Panel | middleware | 1panel |
| 35Mail | middleware | 35mail |
| 35企业邮箱系统 | middleware | 35 |
| 360主机卫士 | middleware | 360 |
| 360新天擎 | middleware | 360 |
| 3CX Phone System | middleware | 3cxphonesystem |
| 53客服 | middleware | 53 |
| 6KBBS | middleware | 6kbbs |
| ABO.CMS | cms | abocms |
| ADB Broadband S.p.A. (Network) | oa | adbbroadbandspanetwork |
| ADTRAN-MX408e | middleware | adtranmx408e |
| ALIBI NVR | iot-device | alibinvr |
| AMH 云主机面板 | middleware | amh |
| ARRIS (Network) | middleware | arrisnetwork |
| ASPCMS | cms | aspcms |
| ASUS AiCloud | middleware | asusaicloud |
| ASUS-DSL-AC52U | middleware | asusdslac52u |
| ASUS-DSL-N14U_B1 | middleware | asusdsln14ub1 |
| ASUS-DSL-N55U | middleware | asusdsln55u |
| ASUS-Modem | middleware | asusmodem |
| ASUS-RT-AC1200 | middleware | asusrtac1200 |
| ASUS-RT-AC3100 | middleware | asusrtac3100 |
| ASUS-RT-AC3200 | middleware | asusrtac3200 |
| ASUS-RT-AC51U | middleware | asusrtac51u |
| ASUS-RT-AC52U | middleware | asusrtac52u |
| ASUS-RT-AC5300 | middleware | asusrtac5300 |
| ASUS-RT-AC53U | middleware | asusrtac53u |
| ASUS-RT-AC55UHP | middleware | asusrtac55uhp |
| ASUS-RT-AC66R | middleware | asusrtac66r |
| ASUS-RT-AC66U | middleware | asusrtac66u |
| ASUS-RT-AC66U_B1 | middleware | asusrtac66ub1 |
| ASUS-RT-AC68P | middleware | asusrtac68p |
| ASUS-Router | iot-device | asusrouter |
| AWX | devops | awx |
| AXIS (network cameras) | iot-device | axisnetworkcameras |
| Aastra-5000 | middleware | aastra5000 |
| Aastra-6731i | middleware | aastra6731i |
| Aastra-6755i | middleware | aastra6755i |
| Aastra-6757i | middleware | aastra6757i |
| Aastra-A5000 | middleware | aastraa5000 |
| Abelcam | middleware | abelcam |
| Abilis (Network/Automation) | middleware | abilisnetworkautomation |
| AccVisio | middleware | accvisio |
| Accellion-Secure-File-Transfer | middleware | accellionsecurefiletransfer |
| Accrisoft | middleware | accrisoft |
| Ace | middleware | ace |
| ActiveHTML | middleware | activehtml |
| Adminer | database | adminer |
| Adobe Campaign Classic | middleware | adobecampaignclassic |
| Adobe-Connect | middleware | adobeconnect |
| Advanced-Electron-Forum | middleware | advancedelectronforum |
| Advantech-LR77 | middleware | advantechlr77 |
| Aethra-Telecommunications-OS | middleware | aethratelecommunicationsos |
| AfterLogic-WebMail | middleware | afterlogicwebmail |
| AfterLogicWebMail系统 | middleware | afterlogicwebmail |
| AirCam-Cameras-and-Surveillance | iot-device | aircamcamerasandsurveillance |
| AirLink-AIC250 | middleware | airlinkaic250 |
| AirLink-SkyIPCam | middleware | airlinkskyipcam |
| AirLink-WL-2600CAM | middleware | airlinkwl2600cam |
| AirLink-modem | middleware | airlinkmodem |
| AirLive-ARM-204 | middleware | airlivearm204 |
| AirLive-Firmware&Driver | middleware | airlivefirmwaredriver |
| AirLive-Modem | middleware | airlivemodem |
| AirLive-Wireless-Device | middleware | airlivewirelessdevice |
| AirOS | middleware | airos |
| Airwatch | middleware | airwatch |
| Akamai CDN | cdn | akamaicdn |
| Akamai-CDN | cdn | akamaicdn |
| Akka HTTP | middleware | akkahttp |
| Alcatel_Lucent-7250 | middleware | alcatellucent7250 |
| Alcatel_Lucent-IP1020 | middleware | alcatellucentip1020 |
| Alcatel_Lucent-Omniswitch | iot-device | alcatellucentomniswitch |
| Alertmanager | observability | alertmanager |
| Alfresco | middleware | alfresco |
| Alibaba Cloud (Block Page) | middleware | alibabacloudblockpage |
| Alibaba Cloud CDN | cdn | alibabacloudcdn |
| Alibaba Druid Monitor | database-tool | alibabadruidmonitor |
| Alienvault | middleware | alienvault |
| Aliyun-Cloud-shield | middleware | aliyuncloudshield |
| AliyunOSS | middleware | aliyunoss |
| Alpha-Five | middleware | alphafive |
| Amazon CloudFront | cdn | amazoncloudfront |
| Amazon-ECS | middleware | amazonecs |
| AnHuiWAF | waf | anhuiwaf |
| AnZuWAF | waf | anzuwaf |
| Angular IO (AngularJS) | middleware | angularioangularjs |
| AnythingLLM | ai-service | anythingllm |
| Apache | middleware | apache |
| Apache APISIX | api-gateway | apacheapisix |
| Apache APISIX Dashboard | gateway | apacheapisixdashboard |
| Apache ActiveMQ | middleware | apacheactivemq |
| Apache Airflow | devops | apacheairflow |
| Apache Druid | middleware | apachedruid |
| Apache Flink | observability | apacheflink |
| Apache Guacamole | middleware | apacheguacamole |
| Apache Haus | middleware | apachehaus |
| Apache NiFi | middleware | apachenifi |
| Apache Ranger | security-device | apacheranger |
| Apache Solr | database | solr |
| Apache Spark | observability | apachespark |
| Apache Superset | observability | apachesuperset |
| Apache Tomcat | middleware | tomcat |
| Apache Tomcat Manager | middleware | apachetomcatmanager |
| Apache Zeppelin | bigdata | apachezeppelin |
| Apache-Cocoon | middleware | apachecocoon |
| Apache-Dubbo | middleware | apachedubbo |
| Apache-OFBiz | middleware | apacheofbiz |
| Apache-RocketMQ | middleware | apacherocketmq |
| Apache-Shiro | framework | apacheshiro |
| Apache-Skywalking | middleware | apacheskywalking |
| Apache-Traffic-Server | middleware | apachetrafficserver |
| Aplikasi | middleware | aplikasi |
| Apollo Config | middleware | apolloconfig |
| Apollo Config Service | middleware | apolloconfigservice |
| Appsmith | lowcode | appsmith |
| Arbor Networks | middleware | arbornetworks |
| Arcadyan o2 box (Network) | middleware | arcadyano2boxnetwork |
| Archivematica | middleware | archivematica |
| Argo CD | cloud-native | argocd |
| Array-VPN | security-device | arrayvpn |
| Arris | middleware | arris |
| Aruba (Virtual Controller) | middleware | arubavirtualcontroller |
| Askey Cable Modem | middleware | askeycablemodem |
| Asustor | middleware | asustor |
| Atlassian | middleware | atlassian |
| Atlassian Confluence | collaboration | atlassianconfluence |
| Atlassian Jira | collaboration | atlassianjira |
| Atlassian – Bamboo | middleware | atlassianbamboo |
| Atlassian – Confluence | middleware | atlassianconfluence |
| Atlassian – JIRA | middleware | atlassianjira |
| Avigilon | middleware | avigilon |
| Avtech IP Surveillance (Camera) | iot-device | avtechipsurveillancecamera |
| Axcient Replibit Management Server | middleware | axcientreplibitmanagementserver |
| Azure Front Door | cdn | azurefrontdoor |
| B2Bbuilder | middleware | b2bbuilder |
| BIG-IP | middleware | bigip |
| BOMGAR Support Portal | middleware | bomgarsupportportal |
| Baidu | middleware | baidu |
| Baidu (IP error page) | middleware | baiduiperrorpage |
| Barracuda | waf | barracuda |
| Barracuda-WAF | waf | barracudawaf |
| Bitnami | middleware | bitnami |
| Blackboard | oa | blackboard |
| Blue Iris (Webcam) | middleware | blueiriswebcam |
| Bluehost | middleware | bluehost |
| Bluetrum-CDN | cdn | bluetrumcdn |
| BoaServer | oa | boaserver |
| Bonobo Git Server | middleware | bonobogitserver |
| Bosch Security Systems (Camera) | iot-device | boschsecuritysystemscamera |
| BrowserCMS | cms | browsercms |
| C-Lodop | middleware | clodop |
| CDN-Cache-Server | cdn | cdncacheserver |
| CDN77 | cdn | cdn77 |
| CX | middleware | cx |
| Cafe24 (Korea) | middleware | cafe24korea |
| Cake PHP | middleware | cakephp |
| Cambium Networks | middleware | cambiumnetworks |
| Camunda | workflow | camunda |
| Canvas LMS (Learning Management) | middleware | canvaslmslearningmanagement |
| CapRover | middleware | caprover |
| CenturyLink Modem GUI Login (eg: Technicolor) | middleware | centurylinkmodemguiloginegtechnicolor |
| Chainpoint | middleware | chainpoint |
| CheckPoint | middleware | checkpoint |
| Checkpoint (Gaia) | middleware | checkpointgaia |
| Chef Automate | middleware | chefautomate |
| Cisco (eg:Conference Room Login Page) | middleware | ciscoegconferenceroomloginpage |
| Cisco Meraki | middleware | ciscomeraki |
| Cisco Meraki Dashboard | oa | ciscomerakidashboard |
| Cisco Router | iot-device | ciscorouter |
| Citrix 虚拟桌面 | middleware | citrix |
| ClaimTime (Ramsell Public Health & Safety) | middleware | claimtimeramsellpublichealthsafety |
| ClickHouse | database | clickhouse |
| ClickHouse HTTP | database | clickhousehttp |
| Cloudflare | cdn | cloudflare |
| Cloudflare CDN | cdn | cloudflarecdn |
| Cloudflare CDN Cache | cdn | cloudflarecdncache |
| Cloudflare DNS | cdn | cloudflaredns |
| Cloudflare Edge Network | cdn | cloudflareedgenetwork |
| Cloudflare WAF Managed Challenge | waf | cloudflarewafmanagedchallenge |
| Cnservers LLC | middleware | cnserversllc |
| Cockpit | cloud-native | cockpit |
| Combivox | middleware | combivox |
| ComfyUI | ai-service | comfyui |
| CommuniGate | middleware | communigate |
| Conpot Honeypot | honeypot | conpothoneypot |
| Consul | middleware | consul |
| Coremail | mail | coremail |
| Cowrie Honeypot | honeypot | cowriehoneypot |
| CradlePoint | middleware | cradlepoint |
| CradlePoint Technology (Router) | iot-device | cradlepointtechnologyrouter |
| CreateLive-Cms | cms | createlivecms |
| CrushFTP | middleware | crushftp |
| CushyCMS | cms | cushycms |
| Cyberoam | oa | cyberoam |
| D-Link (Network) | middleware | dlinknetwork |
| D-Link (camera) | iot-device | dlinkcamera |
| D-Link (router/network) | iot-device | dlinkrouternetwork |
| DBAPPSecurity 安恒信息 | security-device | dbappsecurity |
| DD WRT (DD-WRT milli_httpd) | middleware | ddwrtddwrtmillihttpd |
| DNN (CMS) | cms | dnncms |
| DVR (Korean) | middleware | dvrkorean |
| Dahua | middleware | dahua |
| Dahua DSS | security-device | dahuadss |
| Dahua Storm (DVR) | middleware | dahuastormdvr |
| Dahua Storm (IP Camera) | iot-device | dahuastormipcamera |
| DedeCMS | cms | dedecms |
| Dell SonicWALL | middleware | dellsonicwall |
| Deluge | middleware | deluge |
| Deluge Web UI | middleware | delugewebui |
| Dgraph Ratel | middleware | dgraphratel |
| DianCMS | cms | diancms |
| Dify | ai-service | dify |
| Digital Keystone (DK) | middleware | digitalkeystonedk |
| Digium (Switchvox) | iot-device | digiumswitchvox |
| Discuz! | cms | discuz |
| Django | framework | django |
| Dlink Router | iot-device | dlinkrouter |
| Dlink Webcam | middleware | dlinkwebcam |
| Dnion-CDN | cdn | dnioncdn |
| Docker | middleware | docker |
| DokuWiki | middleware | dokuwiki |
| Domoticz (Home Automation) | middleware | domoticzhomeautomation |
| Dreamer CMS | cms | dreamercms |
| Dreamer CMS-Shiro | framework | dreamercmsshiro |
| Drone CI | devops | droneci |
| Drupal | cms | drupal |
| Dubbo Admin | middleware | dubboadmin |
| DzzOffice 开源办公系统 | middleware | dzzoffice |
| EMQX Dashboard | middleware | emqxdashboard |
| EasyImage | middleware | easyimage |
| EdgePrism-CDN | cdn | edgeprismcdn |
| Elastic (Database) | middleware | elasticdatabase |
| ElasticHD | database-tool | elastichd |
| Elasticsearch | middleware | elasticsearch |
| Elib 图书馆集群管理系统 | middleware | elib |
| Eltex (Router) | iot-device | eltexrouter |
| Endian Firewall | middleware | endianfirewall |
| Entrolink | middleware | entrolink |
| Entronix Energy Management Platform | middleware | entronixenergymanagementplatform |
| Envoy Proxy | api-gateway | envoyproxy |
| Exacq | middleware | exacq |
| Exostar – Managed Access Gateway | security-device | exostarmanagedaccessgateway |
| Express-Node.js | middleware | expressnodejs |
| FE业务协作平台 | middleware | fe |
| FRITZ!Box | middleware | fritzbox |
| Farming Simulator Dedicated Server | middleware | farmingsimulatordedicatedserver |
| FastAPI Docs | framework | fastapidocs |
| FastPanel Hosting | middleware | fastpanelhosting |
| Fastly CDN | cdn | fastlycdn |
| Fastly CDN Cache | cdn | fastlycdncache |
| Fastly Edge Network | cdn | fastlyedgenetwork |
| Ferozo Panel | middleware | ferozopanel |
| Fidion-CMS | cms | fidioncms |
| FineReport | bi | finereport |
| FireEye | middleware | fireeye |
| Fireware Watchguard | middleware | firewarewatchguard |
| FishEye | middleware | fisheye |
| Flask | middleware | flask |
| Flowise | ai-service | flowise |
| Flussonic (Video Streaming) | middleware | flussonicvideostreaming |
| Form.io | middleware | formio |
| FortiGate Endpoint | middleware | fortigateendpoint |
| FortiWeb WAF | waf | fortiwebwaf |
| Fortinet – Forticlient | middleware | fortinetforticlient |
| Fortinet-WAF | waf | fortinetwaf |
| FreeRDP 远程RDP工具 | middleware | freerdprdp |
| Freebox OS | middleware | freeboxos |
| GLPI | middleware | glpi |
| GPON Home Gateway | security-device | gponhomegateway |
| Gargoyle Router Management Utility | iot-device | gargoyleroutermanagementutility |
| Generic WAF Challenge Response | waf | genericwafchallengeresponse |
| Generic WAF SQLi Block | waf | genericwafsqliblock |
| Generic WAF XSS Block | waf | genericwafxssblock |
| Ghost (CMS) | cms | ghostcms |
| GitLab | devops | gitlab |
| Gitea | devops | gitea |
| Gitlab | devops | gitlab |
| GoCDN | cdn | gocdn |
| Gogs | devops | gogs |
| Gradio | ai-service | gradio |
| Grafana | observability | grafana |
| GraphQL | middleware | graphql |
| GraphQL Error Semantics | framework | graphqlerrorsemantics |
| Graylog | observability | graylog |
| Greenbone Security Assistant | security-device | greenbonesecurityassistant |
| H2 Database Console | middleware | h2databaseconsole |
| H3C Device | security-device | h3cdevice |
| H3C SecPath 运维审计系统 | middleware | h3csecpath |
| HAProxy Stats | api-gateway | haproxystats |
| HDWiki | middleware | hdwiki |
| HFS (HTTP File Server) | middleware | hfshttpfileserver |
| HFish Honeypot | honeypot | hfishhoneypot |
| HP Printer / Server | middleware | hpprinterserver |
| HP iLO | middleware | hpilo |
| HTTP/3 Alt-Svc | cdn | http3altsvc |
| HUAWEI Secospace WAF | waf | huaweisecospacewaf |
| Hadoop HDFS NameNode | storage | hadoophdfsnamenode |
| Hadoop YARN ResourceManager | observability | hadoopyarnresourcemanager |
| Handle Proxy | middleware | handleproxy |
| Harbor | devops | harbor |
| HashiCorp Vault | cloud-native | hashicorpvault |
| Hasura Console | api-gateway | hasuraconsole |
| HeroSpeed Digital Technology Co. (NVR/IPC/XVR) | iot-device | herospeeddigitaltechnologyconvripcxvr |
| Hikvision Device | security-device | hikvisiondevice |
| Hikvision IP Camera | iot-device | hikvisionipcamera |
| Hikvision iVMS | security-device | hikvisionivms |
| Hikvision iVMS-5060 | middleware | hikvisionivms5060 |
| Hikvision iVMS-8300 | middleware | hikvisionivms8300 |
| Hikvision-Cameras-and-Surveillance | iot-device | hikvisioncamerasandsurveillance |
| Hillstone 山石网科防火墙 | security-device | hillstone |
| Hitron Technologies | middleware | hitrontechnologies |
| Hitron Technologies Inc. | middleware | hitrontechnologiesinc |
| Homegrown Website Hosting | middleware | homegrownwebsitehosting |
| Honeywell | middleware | honeywell |
| HostMonster - Web hosting | middleware | hostmonsterwebhosting |
| Huawei (Network) | middleware | huaweinetwork |
| Huawei Cloud CDN | cdn | huaweicloudcdn |
| Huawei user-login | middleware | huaweiuserlogin |
| Huawei – ADSL/Router | iot-device | huaweiadslrouter |
| Huawei – Claro | middleware | huaweiclaro |
| Hue | bigdata | hue |
| IBM Notes | middleware | ibmnotes |
| IBM Server | middleware | ibmserver |
| INSTAR Full-HD IP-Camera | iot-device | instarfullhdipcamera |
| INSTAR IP Cameras | iot-device | instaripcameras |
| IP Camera | iot-device | ipcamera |
| ISP Manager | middleware | ispmanager |
| ISP Manager (Web Hosting Panel) | middleware | ispmanagerwebhostingpanel |
| ISPConfig | middleware | ispconfig |
| IW | middleware | iw |
| Icecast Streaming Media Server | middleware | icecaststreamingmediaserver |
| Incapsula-CDN | cdn | incapsulacdn |
| InfiNet Wireless \| WANFleX (Network) | middleware | infinetwirelesswanflexnetwork |
| Influxdb | database | influxdb |
| Inspur-InCloud-Sphere | middleware | inspurincloudsphere |
| Intelbras SA | middleware | intelbrassa |
| Intelbras Wireless | middleware | intelbraswireless |
| JAWS Web Server (IP Camera) | iot-device | jawswebserveripcamera |
| JBoss | middleware | jboss |
| JBoss Application Server 7 | framework | jbossapplicationserver7 |
| JC6金和协同管理平台 | oa | jc6 |
| JFrog Artifactory | devops | jfrogartifactory |
| JIRA | middleware | jira |
| Jaeger UI | observability | jaegerui |
| Jamf Pro Login | middleware | jamfprologin |
| Jboss | framework | jboss |
| JeecgBoot | framework | jeecg |
| Jeedom (home automation) | middleware | jeedomhomeautomation |
| Jellyfin | middleware | jellyfin |
| Jenkins | devops | jenkins |
| Jetty | middleware | jetty |
| Joomla | cms | joomla |
| JumpServer 堡垒机 | security-device | jumpserver |
| Juniper Device Manager | middleware | juniperdevicemanager |
| Jupyter | ai-platform | jupyter |
| Jupyter Notebook | ai-service | jupyternotebook |
| JupyterHub | ai-service | jupyterhub |
| JupyterLab | ai-service | jupyterlab |
| JustHost | middleware | justhost |
| Kafka UI | middleware | kafkaui |
| Keenetic | middleware | keenetic |
| KeepItSafe Management Console | middleware | keepitsafemanagementconsole |
| Kerio Connect (Webmail) | middleware | kerioconnectwebmail |
| Kerio Connect WebMail | middleware | kerioconnectwebmail |
| Kerio Control Firewall | middleware | keriocontrolfirewall |
| KeyHelp (Keyweb AG) | middleware | keyhelpkeywebag |
| Keycloak | cloud-native | keycloak |
| Kibana | observability | kibana |
| Kingdee | erp | kingdee |
| Kingsoft CDN | cdn | kingsoftcdn |
| Kong Gateway | api-gateway | konggateway |
| KoobooCMS | cms | kooboocms |
| KrakenD | api-gateway | krakend |
| KubeSphere | cloud-native | kubesphere |
| Kubeflow | middleware | kubeflow |
| Kubernetes Dashboard | cloud-native | kubernetesdashboard |
| Kyocera (Printer) | middleware | kyoceraprinter |
| LANCOM Systems | middleware | lancomsystems |
| LaCie | middleware | lacie |
| Landray OA | oa | landray |
| Langfuse | ai-service | langfuse |
| Lantronix (Spider) | middleware | lantronixspider |
| Laravel | framework | laravel |
| Laterpay | middleware | laterpay |
| Leadsec-SSL-VPN | security-device | leadsecsslvpn |
| Legendsec 网神防火墙 | security-device | legendsec |
| Lenel | middleware | lenel |
| Liferay Portal | middleware | liferayportal |
| Ligowave (network) | middleware | ligowavenetwork |
| Linksys Smart Wi-Fi | middleware | linksyssmartwifi |
| LiquidFiles | middleware | liquidfiles |
| LiteSpeed | middleware | litespeed |
| Longhorn | cloud-native | longhorn |
| Loxone (Automation) | middleware | loxoneautomation |
| Lucee! | middleware | lucee |
| Luma Surveillance | middleware | lumasurveillance |
| Lupus Electronics XT | middleware | lupuselectronicsxt |
| MDaemon Remote Administration | middleware | mdaemonremoteadministration |
| MDaemon Webmail | middleware | mdaemonwebmail |
| MK-AUTH | middleware | mkauth |
| MLflow | ai-service | mlflow |
| MOBOTIX Camera | iot-device | mobotixcamera |
| MacCMS | cms | maccms |
| Magento | middleware | magento |
| MailWizz | middleware | mailwizz |
| Mailcow | middleware | mailcow |
| MapGIS Server Manager | middleware | mapgisservermanager |
| Material Dashboard | oa | materialdashboard |
| Mautic (Open Source Marketing Automation) | middleware | mauticopensourcemarketingautomation |
| MaxCDN | cdn | maxcdn |
| Mersive Solstice | middleware | mersivesolstice |
| MetInfo | cms | metinfo |
| Metabase | observability | metabase |
| Metasploit | middleware | metasploit |
| MeterSphere | middleware | metersphere |
| Microhard Systems | middleware | microhardsystems |
| Microsoft IIS | middleware | iis |
| Microsoft OWA | middleware | microsoftowa |
| Microsoft Outlook | middleware | microsoftoutlook |
| Microsoft-Ajax-CDN | cdn | microsoftajaxcdn |
| Milvus | database | milvus |
| MinIO | storage | minio |
| MinIO Console | storage | minioconsole |
| Mitel Networks (MiCollab End User Portal) | middleware | mitelnetworksmicollabenduserportal |
| MobileIron | middleware | mobileiron |
| Moodle | middleware | moodle |
| Moxapass ioLogik Remote Ethernet I/O Server | middleware | moxapassiologikremoteethernetioserver |
| Multilaser | middleware | multilaser |
| MyASP | middleware | myasp |
| NEC WebPro | middleware | necwebpro |
| NETASQ - Secure / Stormshield | middleware | netasqsecurestormshield |
| NETGEAR ReadyNAS | iot-device | netgearreadynas |
| NETIASPOT (Network) | middleware | netiaspotnetwork |
| NOS Router | iot-device | nosrouter |
| NPS | middleware | nps |
| NSFOCUS 绿盟安全设备 | middleware | nsfocus |
| NSFOCUS 绿盟科技 | security-device | nsfocus |
| NSFOCUS-WAF | waf | nsfocuswaf |
| NVIDIA Triton Inference Server | ai-service | nvidiatritoninferenceserver |
| Nacos | middleware | nacos |
| Nagios | observability | nagios |
| Neo4j | database | neo4j |
| NetComWireless (Network) | middleware | netcomwirelessnetwork |
| NetData | middleware | netdata |
| Netcom Technology | middleware | netcomtechnology |
| Netdata | observability | netdata |
| Netgear | middleware | netgear |
| Netgear (Network) | middleware | netgearnetwork |
| Netis (network devices) | middleware | netisnetworkdevices |
| Netport Software (DSL) | middleware | netportsoftwaredsl |
| Newdefend WAF | waf | newdefendwaf |
| Nexus Repository Manager | devops | nexusrepositorymanager |
| Nginx | middleware | nginx |
| Nginx Proxy Manager | api-gateway | nginxproxymanager |
| Niagara Web Server | middleware | niagarawebserver |
| Niagara Web Server / Tridium | middleware | niagarawebservertridium |
| Nnetgear 路由器 | iot-device | nnetgear |
| Node-RED | workflow | nodered |
| Nomadix Access Gateway | security-device | nomadixaccessgateway |
| Nucleus-CMS | cms | nucleuscms |
| Nuxt JS | middleware | nuxtjs |
| OPNsense | middleware | opnsense |
| OTRS (Open Ticket Request System) | middleware | otrsopenticketrequestsystem |
| Octoprint (3D printer) | middleware | octoprint3dprinter |
| Odoo | middleware | odoo |
| OkoFEN Pellematic | middleware | okofenpellematic |
| Ollama | ai-platform | ollama |
| Ollama API | ai-service | ollamaapi |
| Onera | middleware | onera |
| Open WebUI | ai-service | openwebui |
| OpenAPI JSON | framework | openapijson |
| OpenAPI JSON Document | api-gateway | openapijsondocument |
| OpenCanary | honeypot | opencanary |
| OpenERP (now known as Odoo) | middleware | openerpnowknownasodoo |
| OpenGeo Suite | middleware | opengeosuite |
| OpenProject | middleware | openproject |
| OpenRG | middleware | openrg |
| OpenSearch Dashboards | observability | opensearchdashboards |
| OpenShift Console | cloud-native | openshiftconsole |
| OpenStack | middleware | openstack |
| OpenUI5 | middleware | openui5 |
| OpenVPN | security-device | openvpn |
| OpenWrt LuCI | iot-device | openwrtluci |
| Openfire Admin Console | middleware | openfireadminconsole |
| Oracle WebLogic | middleware | oracleweblogic |
| Ossia (Provision SR) \| Webcam/IP Camera | iot-device | ossiaprovisionsrwebcamipcamera |
| Outlook Web Application | middleware | outlookwebapplication |
| PHPCMS | cms | phpcms |
| PKP (OpenJournalSystems) Public Knowledge Project | middleware | pkpopenjournalsystemspublicknowledgeproject |
| PLEX Server | middleware | plexserver |
| PRTG Network Monitor | middleware | prtgnetworkmonitor |
| Pagevamp | middleware | pagevamp |
| Palo Alto Login Portal | middleware | paloaltologinportal |
| Palo Alto Networks | middleware | paloaltonetworks |
| Panabit | security-device | panabit |
| Panasonic远程摄像机 | iot-device | panasonic |
| Paradox IP Module | middleware | paradoxipmodule |
| Parallels Default page | middleware | parallelsdefaultpage |
| Parallels Plesk Panel | middleware | parallelspleskpanel |
| Parse | middleware | parse |
| PbootCMS | cms | pbootcms |
| Pi Star | middleware | pistar |
| PigCms | cms | pigcms |
| Plesk | middleware | plesk |
| Plesk 面板 | middleware | plesk |
| Polycom | middleware | polycom |
| Portainer | devops | portainer |
| Portainer (Docker Management) | middleware | portainerdockermanagement |
| PowerCDN | cdn | powercdn |
| PowerMTA monitoring | middleware | powermtamonitoring |
| Prefect Server | devops | prefectserver |
| Prometheus | observability | prometheus |
| Prometheus Time Series Collection and Processing Server | observability | prometheustimeseriescollectionandprocessingserver |
| Proofpoint | middleware | proofpoint |
| Proxmox VE | devops | proxmoxve |
| QNAP NAS Virtualization Station | iot-device | qnapnasvirtualizationstation |
| QUIC Version Negotiation | cdn | quicversionnegotiation |
| Qdrant Dashboard | database | qdrantdashboard |
| QiAnXin 奇安信 | security-device | qianxin |
| RADIX | middleware | radix |
| RabbitMQ | middleware | rabbitmq |
| RabbitMQ Management | middleware | rabbitmqmanagement |
| RackCache | middleware | rackcache |
| RackCorp-CDN | cdn | rackcorpcdn |
| Rancher | cloud-native | rancher |
| Ray Dashboard | ai-service | raydashboard |
| Realtek | middleware | realtek |
| Redash | observability | redash |
| RedisInsight | database | redisinsight |
| Redmine | middleware | redmine |
| RemObjects SDK / Remoting SDK for .NET HTTP Server Microsoft | middleware | remobjectssdkremotingsdkfornethttpservermicrosoft |
| Reolink | middleware | reolink |
| Residential Gateway | security-device | residentialgateway |
| Reyzar-CDN | cdn | reyzarcdn |
| Ricoh | middleware | ricoh |
| Rocket Chat | middleware | rocketchat |
| RocketMQ Console | middleware | rocketmqconsole |
| RoundCube Webmail | middleware | roundcubewebmail |
| Roundcube Webmail | middleware | roundcubewebmail |
| Ruckus Wireless | middleware | ruckuswireless |
| Ruijie Device | security-device | ruijiedevice |
| Rumpus | middleware | rumpus |
| Rundeck | devops | rundeck |
| RuoYi 若依 | framework | ruoyi |
| SAP Conversational AI | middleware | sapconversationalai |
| SAP ID Service: Log On | middleware | sapidservicelogon |
| SAP Netweaver | middleware | sapnetweaver |
| SOYAL Serial Device Server | middleware | soyalserialdeviceserver |
| STARFACE VoIP Software | middleware | starfacevoipsoftware |
| Safe3WAF | waf | safe3waf |
| Safedog | waf | safedog |
| Saia Burgess Controls – PCD | middleware | saiaburgesscontrolspcd |
| Sails | middleware | sails |
| Salesforce | middleware | salesforce |
| Sangfor | middleware | sangfor |
| Sangfor Device | security-device | sangfordevice |
| Sangfor 应用交付报表系统 | middleware | sangfor |
| Seafile | middleware | seafile |
| Seagate Technology (NAS) | iot-device | seagatetechnologynas |
| SeaweedFS | middleware | seaweedfs |
| Securepoint | middleware | securepoint |
| Seeyon 致远 OA | oa | seeyonoa |
| Sentinel Dashboard | middleware | sentineldashboard |
| Sentora | middleware | sentora |
| Sentry | observability | sentry |
| ServiceNow | middleware | servicenow |
| Shenzhen coship electronics co. | middleware | shenzhencoshipelectronicsco |
| Shinobi (CCTV) | middleware | shinobicctv |
| Shock&Innovation!! netis setup | middleware | shockinnovationnetissetup |
| Shop7Z | middleware | shop7z |
| Shoutcast Server | middleware | shoutcastserver |
| ShowDoc | middleware | showdoc |
| Siemens OZW772 | middleware | siemensozw772 |
| Sierra Wireless Ace Manager (Airlink) | middleware | sierrawirelessacemanagerairlink |
| SimpleHelp (Remote Support) | middleware | simplehelpremotesupport |
| Sina-CDN | cdn | sinacdn |
| Skype | middleware | skype |
| Slack | middleware | slack |
| SmartLAN/G | middleware | smartlang |
| SmartPing | middleware | smartping |
| SmarterMail | middleware | smartermail |
| Solar 网络管理系统 | middleware | solar |
| Solarwinds Serv-U FTP Server | middleware | solarwindsservuftpserver |
| SonarQube | devops | sonarqube |
| Sonatype Nexus Repository Manager | devops | sonatypenexusrepositorymanager |
| SonicWALL | middleware | sonicwall |
| Sophos Cyberoam (appliance) | oa | sophoscyberoamappliance |
| Sophos User Portal/VPN Portal | security-device | sophosuserportalvpnportal |
| SpamExperts | middleware | spamexperts |
| Spiceworks (panel) | middleware | spiceworkspanel |
| Spring Boot | framework | spring, springboot |
| Spring Boot Actuator | framework | springbootactuator |
| Spring Boot Actuator Health | framework | springbootactuatorhealth |
| Spring Boot Admin | observability | springbootadmin |
| Spring Cloud Gateway | api-gateway | springcloudgateway |
| Squid | middleware | squid |
| Streamlit | ai-service | streamlit |
| StruxureWare (Schneider Electric) | middleware | struxurewareschneiderelectric |
| Subrion-CMS | cms | subrioncms |
| SuiteCRM | middleware | suitecrm |
| Sunny WebBox | middleware | sunnywebbox |
| SuperMap iServer Web Manager | middleware | supermapiserverwebmanager |
| Supermicro Intelligent Management (IPMI) | middleware | supermicrointelligentmanagementipmi |
| Supersized | middleware | supersized |
| Surfilter SSL VPN Portal | security-device | surfiltersslvpnportal |
| Swagger UI | api-doc | swaggerui |
| SyncThru Web Service (Printers) | middleware | syncthruwebserviceprinters |
| Synology DiskStation | middleware | synologydiskstation |
| Synology VPN Plus | security-device | synologyvpnplus |
| T-Pot Honeypot | honeypot | tpothoneypot |
| TC-Group | middleware | tcgroup |
| TCN | middleware | tcn |
| TOTOLINK (network) | middleware | totolinknetwork |
| TP-LINK (Network Device) | middleware | tplinknetworkdevice |
| TP-LINK 产品 | middleware | tplink |
| TPshop-cms | cms | tpshopcms |
| TVT 公司产品 | middleware | tvt |
| Tableau | middleware | tableau |
| Tandberg | middleware | tandberg |
| TeamCity | devops | teamcity |
| Technicolor | middleware | technicolor |
| Technicolor / Thomson Speedtouch (Network / ADSL) | middleware | technicolorthomsonspeedtouchnetworkadsl |
| Technicolor Gateway | security-device | technicolorgateway |
| Tecvoz | middleware | tecvoz |
| Teltonika | middleware | teltonika |
| Temporal Web | devops | temporalweb |
| Tencent Cloud CDN | cdn | tencentcloudcdn |
| Tencent-CDN | cdn | tencentcdn |
| Tencent-Exmail | middleware | tencentexmail |
| Tenda Web Master | middleware | tendawebmaster |
| Tenon-iTools | middleware | tenonitools |
| TensorBoard | ai-service | tensorboard |
| Thanos | observability | thanos |
| ThinVNC | middleware | thinvnc |
| ThingsBoard | iot-device | thingsboard |
| ThinkPHP | framework | thinkphp |
| ThinkSNS | middleware | thinksns |
| TilginAB (HomeGateway) | security-device | tilginabhomegateway |
| TomatoCMS | cms | tomatocms |
| Tongda | middleware | tongda |
| Tongda 通达 OA | oa | tongdaoa |
| Topsec Device | security-device | topsecdevice |
| Topsec 天融信 | security-device | topsec |
| Traccar GPS tracking | middleware | traccargpstracking |
| Traefik | api-gateway | traefik |
| Trendnet IP camera | iot-device | trendnetipcamera |
| Twonky Server (Media Streaming) | middleware | twonkyservermediastreaming |
| Tyk Dashboard | api-gateway | tykdashboard |
| UBNT Router UI | iot-device | ubntrouterui |
| UCloud-CDN | cdn | ucloudcdn |
| UPC Ceska Republica (Network) | middleware | upcceskarepublicanetwork |
| UQCMS(UQ云商) | cms | uqcmsuq |
| Ubiquiti Aircube | middleware | ubiquitiaircube |
| Ubiquiti Login Portals | middleware | ubiquitiloginportals |
| Ubiquiti UNMS | middleware | ubiquitiunms |
| Ubiquiti – AirOS | middleware | ubiquitiairos |
| UniFi Video Controller (airVision) | middleware | unifivideocontrollerairvision |
| Unified Management Console (Polycom) | middleware | unifiedmanagementconsolepolycom |
| Univention Portal | middleware | univentionportal |
| Universal Devices (UD) | middleware | universaldevicesud |
| Universal Route Behavior | honeypot | universalroutebehavior |
| Université Toulouse 1 Capitole | middleware | universittoulouse1capitole |
| Untangle | middleware | untangle |
| VMware Horizon | middleware | vmwarehorizon |
| VMware Workspace ONE Access | middleware | vmwareworkspaceoneaccess |
| VZPP Plesk | middleware | vzppplesk |
| Vanderbilt SPC | middleware | vanderbiltspc |
| Venustech 启明星辰 | security-device | venustech |
| Verizon-CDN | cdn | verizoncdn |
| Vesta Hosting Control Panel | middleware | vestahostingcontrolpanel |
| VictoriaMetrics | observability | victoriametrics |
| Vigbo | middleware | vigbo |
| Vigor Router | iot-device | vigorrouter |
| VisualSVN Server | middleware | visualsvnserver |
| Vivotek (Camera) | iot-device | vivotekcamera |
| Vmware Secure File Transfer | middleware | vmwaresecurefiletransfer |
| Vodafone (Technicolor) | middleware | vodafonetechnicolor |
| Voole-OTV | middleware | vooleotv |
| WAMPSERVER | middleware | wampserver |
| WHM | middleware | whm |
| WISPR (Airlan) | middleware | wisprairlan |
| WS CDN Server | cdn | wscdnserver |
| WatchGuard | middleware | watchguard |
| Wazuh Dashboard | security-device | wazuhdashboard |
| Weaver e-cology | oa | weaverecology |
| Weaver e-mobile | oa | ecology, weaver |
| Weaver e-office | oa | weavereoffice |
| Weaviate | database | weaviate |
| Web Client Pro | middleware | webclientpro |
| WebLogic Console | middleware | weblogicconsole |
| WebRay-WAF | waf | webraywaf |
| WebYep CMS | cms | webyepcms |
| Webmin | middleware | webmin |
| Websecurity-WAF | waf | websecuritywaf |
| Websecurity_WAF | waf | websecuritywaf |
| WebsiteBaker-CMS | cms | websitebakercms |
| WebsiteBakerCMS | cms | websitebakercms |
| Websockets test page (eg: port 5900) | middleware | websocketstestpageegport5900 |
| Western-Digital | middleware | westerndigital |
| WiJungle | middleware | wijungle |
| WildFly | middleware | wildfly |
| Wildfly | framework | wildfly |
| WindRiver-WebServer | middleware | windriverwebserver |
| Windows Azure | middleware | windowsazure |
| WiseGrid慧敏应用交付网关 | security-device | wisegrid |
| Wisenet NVR | iot-device | wisenetnvr |
| WordPress | cms | wordpress |
| Wordpress Under Construction Icon | cms | wordpressunderconstructionicon |
| Workday | middleware | workday |
| WorldClient for Mdaemon | middleware | worldclientformdaemon |
| XAMPP | middleware | xampp |
| XXL-JOB | middleware | xxljob |
| XYHCMS | cms | xyhcms |
| Xitami | middleware | xitami |
| Yasni | middleware | yasni |
| Yii PHP Framework (Default Favicon) | middleware | yiiphpframeworkdefaultfavicon |
| Yonyou NC | erp | yonyounc |
| Yonyou U8/GRP-U8 | erp | yonyouu8grpu8 |
| Yxlink-WAF | waf | yxlinkwaf |
| ZTE (Network) | middleware | ztenetwork |
| ZTE Corporation (Gateway/Appliance) | security-device | ztecorporationgatewayappliance |
| ZURB Foundation | middleware | zurbfoundation |
| Zabbix | observability | zabbix |
| Zhejiang Uniview Technologies Co. | middleware | zhejianguniviewtechnologiesco |
| ZikulaCMS | cms | zikulacms |
| Zipkin | observability | zipkin |
| ZyXEL | middleware | zyxel |
| ZyXEL (Network) | middleware | zyxelnetwork |
| Zyxel ZyWALL | middleware | zyxelzywall |
| a2b-Webserver | middleware | a2bwebserver |
| activeWeb-Content-Server | middleware | activewebcontentserver |
| bet365 | middleware | bet365 |
| bintec elmeg | middleware | bintecelmeg |
| cPanel-Login | middleware | cpanellogin |
| cPanel-WHM | middleware | cpanelwhm |
| cacaoweb | middleware | cacaoweb |
| cm3-cms | cms | cm3cms |
| django CMS | cms | djangocms |
| e-cology 运维管理平台 | oa | ecology, weaver |
| f5 Big IP | middleware | f5bigip |
| fidion CMS | cms | fidioncms |
| fortinet-forticlient | middleware | fortinetforticlient |
| iDirect Canada (Network Management) | middleware | idirectcanadanetworkmanagement |
| iKuai Networks | middleware | ikuainetworks |
| iOffice(红帆oa) | oa | iofficeoa |
| iPECS | middleware | ipecs |
| idera | middleware | idera |
| innovaphone | middleware | innovaphone |
| iomega NAS | iot-device | iomeganas |
| keycdn-engine | cdn | keycdnengine |
| lwIP (A Lightweight TCP/IP stack) | middleware | lwipalightweighttcpipstack |
| macOS Server (Apple) | middleware | macosserverapple |
| mofinetwork | middleware | mofinetwork |
| mongo-express | database | mongoexpress |
| motionEye (camera) | iot-device | motioneyecamera |
| n8n | workflow | n8n |
| netdata dashboard | oa | netdatadashboard |
| openWRT Luci | middleware | openwrtluci |
| openmediavault (NAS) | iot-device | openmediavaultnas |
| ownCloud | middleware | owncloud |
| pfSense | middleware | pfsense |
| pgAdmin | database | pgadmin |
| phpMyAdmin | database-tool | phpmyadmin |
| phpPgAdmin | database-tool | phppgadmin |
| semcms外贸网站(多语言版) | cms | semcms |
| slack-instance | middleware | slackinstance |
| truVision (NVR) | iot-device | truvisionnvr |
| truVision NVR (interlogix) | iot-device | truvisionnvrinterlogix |
| wdCP cloud host management system | middleware | wdcpcloudhostmanagementsystem |
| wdCP 云主机面板 | middleware | wdcp |
| УТМ (Federal Service for Alcohol Market Regulation \| Russia) | middleware | federalserviceforalcoholmarketregulationrussia |
| 万户ezOFFICE | middleware | ezoffice |
| 即会通企业版(LiveUC)\|视频会议 | middleware | liveuc |
| 友加畅捷U+财会通 | middleware | u |
| 宝塔-BT.cn | middleware | btcn |
| 慧林ICP/iP备案系统 | middleware | icpip |
| 明源云MIP集成平台 | middleware | mip |
| 机器人控制系统（RCS-2000） | middleware | rcs2000 |
| 泛微 OA (e-cology) | oa | oaecology |
| 泛微-EMobile | oa | ecology, weaver |
| 海康威视（Hikvision） | middleware | hikvision |
| 用友 E-HR | oa | ehr |
| 用友-FE协同办公平台 | oa | fe |
| 用友BIP 数据应用服务 | oa | bip |
| 用友GRP-U8 | oa | grpu8 |
| 用友GRP-U8 新政府会计制度专版 | oa | grpu8 |
| 用友GRP-U8(财务系统) | oa | grpu8 |
| 用友TurboCRM | oa | turbocrm |
| 用友优普U8系统 | oa | u8 |
| 红海eHR人力资源管理系统 | middleware | ehr |
| 网神SecWAF应用防火墙 | waf | secwaf |
| 网防G01 | middleware | g01 |
| 金蝶K/3 Cloud | oa | k3cloud |
| 锐捷 NBR 路由器 | iot-device | nbr |
| 锐捷 Ruijie Networks | middleware | ruijienetworks |
| 锐捷 SSL VPN | security-device | sslvpn |
| 飞思网巡 IT运维系统 | middleware | it |
| 骑士 74CMS | cms | 74cms |

## 二、仅识别、未关联 POC 的指纹（被跳过）

| 指纹名 | 类别 |
|---|---|
| ASP.NET | language |
| Amazon | middleware |
| Apple | middleware |
| Dell | middleware |
| Golang | middleware |
| Google | middleware |
| Huawei | middleware |
| Java | language |
| Netflix | middleware |
| Node.js | language |
| PHP | language |
| Python | language |
| React | middleware |
| Ruby | language |
| WAF | waf |
| 中成科信 综合管理平台 | middleware |
| 二级域名分发系统 | middleware |
| 信呼 OA | oa |
| 信锐物联平台 | middleware |
| 加速乐 | cdn |
| 北京朗新天霁人力资源系统 | middleware |
| 华测监测预警系统 | middleware |
| 协众OA | oa |
| 协达OA | oa |
| 多媒体信息发布系统 | middleware |
| 天智智慧医院综合质量监管平台 | middleware |
| 天融信VPN | security-device |
| 天融信VPN设备 | security-device |
| 天融信设备 | middleware |
| 奇安信自动化渗透测试系统 | middleware |
| 奥联通讯管理平台 | middleware |
| 字节数联云桌面系统 | middleware |
| 字节跳动云负载均衡 | middleware |
| 孚盟云 CRM | middleware |
| 悟空CRM | middleware |
| 慧星自来水营业管理信息系统 | middleware |
| 护卫神·主机大师 | middleware |
| 指挥调度平台 | middleware |
| 明源云ERP | middleware |
| 明致 OA | oa |
| 晶奇科技救助管理系统 | middleware |
| 极限OA网络智能办公系统 | oa |
| 泛微 OA | oa |
| 流量通 流量平台 | middleware |
| 海康威视综合安防管理平台 | middleware |
| 深信服下一代防火墙管理系统 | waf |
| 用友-商战实践平台 | oa |
| 畅捷CRM | middleware |
| 百傲瑞达 | middleware |
| 禅道 | middleware |
| 移动云 WAF | waf |
| 网宿-CDN | cdn |
| 网康科技网关/防火墙 | waf |
| 致远互联-协同数据分析云 | oa |
| 资产灯塔系统 | middleware |
| 迈普多业务融合网关 | security-device |
| 迪浪云OA | oa |
| 金睛云华高级威胁检测系统 | middleware |
| 金蝶云星空 移动应用管理平台 | oa |
| 金钟集团智能物流管理系统 | middleware |
| 银达汇智智慧综合管理平台 | middleware |
| 阿里云-CDN | cdn |
