[![New Relic Experimental header](https://github.com/newrelic/opensource-website/raw/master/src/images/categories/Experimental.png)](https://opensource.newrelic.com/oss-category/#new-relic-experimental)

# New Relic integration for Microsoft Hyper-V reporting (nri-hyperv-report)

On-Host Integration for New Relic Infrastructure to collect inventory and health data about Hyper-V Clusters, Hosts, VMs, and their constituents.

## Installation

1. Run `install.ps1` as Administrator.

## Requirements

* New Relic Infrastructure Agent for Windows must be installed.

### Hyper-V Targets (Clustered or Standalone)
  * Active Directory domain membership
  * Supported Operating Systems
    - Windows Server 2012
    - Windows Server 2012 R2
    - Windows Server 2016
    - Hyper-V Server 2012
    - Hyper-V Server 2012 R2
    - Hyper-V Server 2016

### nri-hyperv-report Scripts
  * Can be run directly on a Hyper-V target or on a remote Windows host
  * Same or trusted Active Directory domain membership with Hyper-V target
  * Supported Operating Systems
    - Windows Server 2012
    - Windows Server 2012 R2
    - Windows 8
    - Windows 8.1
    - Windows 10
  * Windows PowerShell 3.0 or 4.0 (installed by default on supported server OSes)
  * Administrative privileges on the target Hyper-V server(s)

## Data Collection Details

### Clusters
  * Pyhsical Resources
    - Node
    - Processor
    - Memory
    - Storage
  * Virtual Resources
    - vMachine
    - vProcessor
    - vMemory
    - vStorage

### Hyper-V Hosts (Clustered or Standalone)
  * Hostname
    - Computer Manufacturer, Model
  * Operating System Version
  * State
  * Uptime
  * Domain Name
  * Total and Running VM Count
    - Detailed as Clustered and Non-clustered
  * Processor Count
    - Logical processor count
    - Physical processor socket count
    - Processor Manufacturer, Model, Ghz
    - Hyper-Threading state for Intel processor
    - Virtual Processors per Logical Processor ratio
  * Used Physical RAM
  * Free Physical RAM
  * Total Physical RAM

### Disks/Volumes (Clustered or Standalone)
  * Name
    - Volume Name (Local Volume, Clustered Volume, Cluster Shared Volume)
    - Volume label or CSV path
    - Disk name (Physical Disk, Clustered Disk)
    - Total/Allocated/Unallocated physical disk size
  * Disk/Volume State
  * Usage (Logical Partition, Cluster Volume, Cluster Shared Volume, Quorum, System Volume, Pass-through, Unassigned)
  * Owner
  * Physical Disk Bus Type
  * Volume File System
  * Active VHD (Storage Overcommitment)
  * Used Size
  * Free Size
  * Total Size

### Virtual Machines
  * Name
    - VM name
    - Configuration XML path
    - Generation
    - Version
  * State
  * Uptime
  * Owner
    * Owner hostname
  * Virtual Processor
    * Count
  * Virtual RAM
    - Startup
    - Minimum (if dynamic memory enabled)
    - Maximum (if dynamic memory enabled)
    - Assigned
  * Integration Services
    - State (UpToDate, UpdateRequired, MayBeRequired, NotDetected)
    - Version number
  * Checkpoint
    - Checkpoint state
    - Checkpoint count (if exists)
    - Checkpoint chain (if exists)
  * Replica
    - Replication State and Health
    - Primary, Replica and Extended modes
    - Replica Server or Primary Server
    - Replication Frequency
    - Last Replication Time
  * Disk
    - VHD Name
    - VHD File Path
    - Current VHD file size
    - Maximum VHD disk size
    - VHD Type
    - Controller Type
    - VHD fragmentation percent
    - Includes pass-through disks (if exist)
    - Includes differencing virtual disk chain (if exists)
    - Missing VHD files
  * Network Adapter
    - Device type
    - Connection status
    - Virtual switch name
    - IP address
    - VLAN ID
    - MAC Address
    - MAC Type
    - DHCP Guard
    - Router Guard
    - Port Mirroring
    - Protected Network
  * Missing VHD files
  * Clustered VM
    - State
    - Configuration resource problems (i.e. offline)

## Support

New Relic has open-sourced this project. This project is provided AS-IS WITHOUT WARRANTY OR DEDICATED SUPPORT. Issues and contributions should be reported to the project here on GitHub. We encourage you to bring your experiences and questions to the [Explorers Hub](https://discuss.newrelic.com) where our community members collaborate on solutions and new ideas.

## Contributing

We encourage your contributions to improve AWS Silver Lining! Keep in mind when you submit your pull request, you'll need to sign the CLA via the click-through using CLA-Assistant. You only have to sign the CLA one time per project. If you have any questions, or to execute our corporate CLA, required if your contribution is on behalf of a company, please drop us an email at opensource@newrelic.com.

**A note about vulnerabilities**

As noted in our [security policy](../../security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [HackerOne](https://hackerone.com/newrelic).

## License

nri-hyperv-report is licensed under the [Apache 2.0](http://apache.org/licenses/LICENSE-2.0.txt) License.
