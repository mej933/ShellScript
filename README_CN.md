# 個人Shell Scirpt彙總

該項目是個人Shell Script的彙總，每一個腳本都有其特定的作用。腳本主題涵蓋 **系統信息檢測**、**系統初始化配置**、**軟件安裝配置**、**個人小工具** 等。力求兼容主流的GNU/Linux發行版，如[RHEL][rhel]/[CentOS][centos]/[Fedora][fedora], [Debian][debian]/[Ubuntu][ubuntu], [SLES][sles]/[OpenSUSE][opensuse]。


## 目錄索引
1. [說明](#說明)  
1.1 [幫助信息](#幫助信息)  
2. [GNU/Linux](#gnulinux)  
2.1 [發行版相關信息](#發行版相關信息)  
2.2 [系統優化](#系統優化)  
2.3 [系統工具](#系統工具)  
2.4 [桌面環境](#桌面環境)  
3. [應用程序](#應用程序)  
3.1 [編程語言](#編程語言)  
3.2 [Web服務器](#web服務器)  
3.3 [數據庫系統](#數據庫系統)  
3.4 [容器](#容器)  
3.5 [監控](#監控)  
3.6 [搜索](#搜索)  
3.7 [辦公套件](#辦公套件)  
4. [工具](#工具)  
5. [參考書目](#參考書目)  


*注*：TOC通過腳本[markdownTOCGeneration.sh](./assets/tool/markdownTOCGeneration.sh)生成。

## 說明
腳本已使用[ShellCheck][shellcheck]工具檢驗，根據實際情況進行修正。

Shell Script目錄快速跳轉
1. [GNU/Linux](./assets/gnulinux "GNU/Linux系統相關")
2. [Software](./assets/software "軟件安裝、更新")
3. [Tools](./assets/tool "個人小工具")


### 幫助信息
在腳本執行命令後添加參數`-h`可查看具體使用說明，此處以腳本`gnuLinuxOfficialDocumentationDownload.sh`爲例：

```bash
# bash gnuLinuxOfficialDocumentationDownload.sh -h
# curl -fsL https://raw.githubusercontent.com/MaxdSre/ShellScript/master/assets/gnulinux/gnuLinuxOfficialDocumentationDownload.sh.sh | sudo bash -s -- -h

Usage:
    script [options] ...
    script | sudo bash -s -- [options] ...

Download RedHat/SUSE/OpenSUSE/AWS Official Product Documentations On GNU/Linux
This script requires superuser privileges (eg. root, su).

[available option]
    -h    --help, show help info
    -d distro_name    --specify GNU/Linux distribution name (Red Hat/SUSE/OpenSUSE/AWS)
    -c    --category choose, default download all categories under specific product
    -t file_type    --specify file type (pdf|epub), default is pdf
    -s save_dir    --specify documentation save path (e.g. /tmp), default is ~ or ~/Downloads
    -p [protocol:]ip:port    --proxy host (http|https|socks4|socks5), default protocol is http
```

**Attention**: 倉庫中的Shell Script優先滿足個人使用需求。

## GNU/Linux
GNU/Linux系統相關

### 發行版相關信息
No.|Simple Description|Code Link
---|---|---
1|GNU/Linux發行版本信息偵測|[code link](./assets/gnulinux/gnuLinuxDistroVersionDetection.sh)
2|GNU/Linux發行版生命週期偵測|[code link](/assets/gnulinux/gnuLinuxLifeCycleInfo.sh)
3|GNU/Linux發行版官方產品文檔下載(PDF/ePub)|[code link](/assets/gnulinux/gnuLinuxOfficialDocumentationDownload.sh)


### 系統優化
No.|Simple Description|Code Link
---|---|---
1|系統初始化設置|[code link](./assets/gnulinux/gnuLinuxPostInstallationConfiguration.sh)
2|防火墙配置(ufw/iptables/firewalld/SuSEfirewall2)|[code link](./assets/gnulinux/gnuLinuxFirewallRuleConfiguration.sh)

**說明**： 該腳本同時支持 [RHEL][rhel]/[CentOS][centos]/[Fedora][fedora]/[Debian][debian]/[Ubuntu][ubuntu]/[OpenSUSE][opensuse]等重要的發行版本。


### 系統工具
No.|Simple Description|Code Link
---|---|---
1|GNU/Linux監聽中的端口及對應服務偵測|[code link](./assets/gnulinux/gnuLinuxPortUsedInfoDetection.sh)
2|GNU/Linux隨機端口號生成|[code link](./assets/gnulinux/gnuLinuxRandomUnusedPortGeneration.sh)


### 桌面環境
No.|Simple Description|Code Link
---|---|---
1|[GNOME][gnome]桌面環境配置|[code link](./assets/gnulinux/GnomeDesktopConfiguration.sh)


## 應用程序
軟件安裝與更新

### 編程語言
No.|Simple Description|Code Link
---|---|---
1|[Golang][golang]|[code link](./assets/software/Golang.sh)
2|[Node.js][nodejs]|[code link](./assets/software/Nodejs.sh)
3|[Oracle SE JDK][oraclesejdk]|[code link](./assets/software/OracleSEJDK.sh)


### Web服務器
No.|Simple Description|Code Link
---|---|---
1|[Nginx][nginxwebserver] Web服務器|[code link](./assets/software/NginxWebServer.sh)
2|[OpenResty][openresty] Web平臺|[code link](./assets/software/OpenResty.sh)


### 數據庫系統
No.|Simple Description|Code Link
---|---|---
1|[MySQL][mysqlce]/[MariaDB][mariadb]/[Percona][percona] 數據庫系統|[code link](./assets/software/MySQLVariants.sh)
2|[MongoDB][mongodbce]社區版|[code link](./assets/software/MongoDB.sh)

### 容器
No.|Simple Description|Code Link
---|---|---
1|[Docker CE][dockerce] 容器 (社區版)|[code link](./assets/software/Docker-CE.sh)


### 監控
No.|Simple Description|Code Link
---|---|---
1|[Grafana][grafana]|[code link](./assets/software/Grafana.sh)
2|[Prometheus][prometheus] (部分完成)|[code link](./assets/software/Prometheus.sh)


### 搜索
No.|Simple Description|Code Link
---|---|---
1|[Elastic][elastic] Stack|[code link](./assets/software/ElacticStack.sh)



### 辦公套件
No.|Simple Description|Code Link
---|---|---
1|[SRWare Iron][srwareiron] 瀏覽器|[code link](./assets/software/SRWareIron.sh)
2|[Mozilla 火狐][mozillafirefox]瀏覽器|[code link](./assets/software/MozillaFirefox.sh)
3|[Libre Office][libreoffice]| 辦公套件|[code link](./assets/software/LibreOffice.sh)
4|[Mozilla ThunderBird][mozillathunderbird] 郵件客戶端|[code link](./assets/software/MozillaThunderbird.sh)
5|[FileZilla FTP][filezillaftp] 客戶端|[code link](./assets/software/FileZilla.sh)
6|[Atom][atomtexteditor] 文本編輯器|[code link](./assets/software/AtomEditor.sh)
7|[Sublime Text 3][sublimetext3] 文本編輯器|[code link](./assets/software/SublimeText.sh)



## 工具
個人小工具

No.|Simple Description|Code Link
---|---|---
1|Markdown TOC 目錄創建|[code link](./assets/tool/markdownTOCGeneration.sh)
2|從[GitHub][github]下載單個文件|[code link](./assets/tool/GitHubSingleFileDownload.sh)
3|代理IP提取|[code link](./assets/tool/proxyIPExtractation.sh)
4|網絡代理自動配置|[code link](./assets/tool/networkProxyAutoConfiguration.sh)
5|MySQL/MariaDB/Percona與GNU/Linux的支持[關係表](https://raw.githubusercontent.com/MaxdSre/ShellScript/master/sources/mysqlVariantsVersionAndLinuxDistroRelationTable.txt)|[code link](./assets/tool/mysqlVariantsVersionAndLinuxDistroRelationTable.sh)


## 參考書目
* [GNU Operating System](https://www.gnu.org/)


[rhel]:https://www.redhat.com/en "RedHat"
[centos]:https://www.centos.org/ "CentOS"
[fedora]:https://getfedora.org/ "Fedora"
[debian]:https://www.debian.org/ "Debian"
[ubuntu]:https://www.ubuntu.com/ "Ubuntu"
[sles]:https://www.suse.com/ "SUSE"
[opensuse]:https://www.opensuse.org/ "OpenSUSE"
[shellcheck]:https://www.shellcheck.net/ "ShellCheck"
[github]:https://github.com "GitHub"

[gnome]:https://www.gnome.org/gnome-3/ "Gnome 3"
[srwareiron]:https://www.srware.net/en/software_srware_iron.php "SRWare Iron Browser"
[mozillafirefox]:https://www.mozilla.org/en-US/firefox/ "Mozilla Firefox Browser"
[libreoffice]:https://www.libreoffice.org/ "LibreOffice - Free Office Suite"
[mozillathunderbird]:https://www.mozilla.org/en-US/thunderbird/ "Mozilla ThunderBird"
[filezillaftp]:https://filezilla-project.org/ "FileZilla - The free FTP solution"
[atomtexteditor]:https://atom.io/ "Atom - A hackable text editor for the 21st Century"
[sublimetext3]:https://www.sublimetext.com/ "Sublime Text - A sophisticated text editor for code, markup and prose"
[grafana]:https://grafana.com/ "Grafana - The open platform for beautiful analytics and monitoring"
[prometheus]:https://prometheus.io/ "Power your metrics and alerting with a leading open-source monitoring solution."
[elastic]:https://www.elastic.co/ "Open Source Search & Analytics · Elasticsearch"
[dockerce]:https://www.docker.com/community-edition "Docker - Build,Ship,and Run Anywhere"
[golang]:https://golang.org/ "The Go Programming Language"
[nodejs]:https://nodejs.org/en/ "Node.js® is a JavaScript runtime built on Chrome's V8 JavaScript engine."
[oraclesejdk]:http://www.oracle.com/technetwork/java/javase/downloads/index.html "Java Platform, Standard Edition"
[nginxwebserver]:https://nginx.org/ "NGINX is a free, open-source, high-performance HTTP server and reverse proxy, as well as an IMAP/POP3 proxy server."
[openresty]:https://openresty.org/en/ "OpenResty® is a full-fledged web platform that integrates the standard Nginx core, LuaJIT, many carefully written Lua libraries, lots of high quality 3rd-party Nginx modules, and most of their external dependencies."
[mysqlce]:https://www.mysql.com/products/community/ "MySQL Community Edition is the freely downloadable version of the world's most popular open source database."
[percona]:https://www.percona.com/ "The Database Performance Experts"
[mariadb]:https://mariadb.org/ "One of the most popular database servers. Made by the original developers of MySQL. Guaranteed to stay open source."
[mongodbce]:https://www.mongodb.com/ "MongoDB is an open-source document database that provides high performance, high availability, and automatic scaling."

<!-- Readme End -->
