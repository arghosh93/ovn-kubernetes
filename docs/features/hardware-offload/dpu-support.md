## DPU support

With the emergence of [Data Processing Units](https://blogs.nvidia.com/blog/2020/05/20/whats-a-dpu-data-processing-unit/) (DPUs), 
NIC vendors can now offer greater hardware acceleration capability, flexibility and security. 

It is desirable to leverage DPU in OVN-kubernetes to accelerate networking and secure the network control plane.

A DPU consists of:
- Industry-standard, high-performance, software-programmable multi-core CPU
- High-performance network interface
- Flexible and programmable acceleration engines

Similarly to Smart-NICs, a DPU follows the kernel switchdev model.
In this model, every VF/PF net-device on the host has a corresponding representor net-device existing
on the embedded CPU.

Any vendor that manufactures a DPU which supports the above model should work with current design.

Design document can be found [here](https://docs.google.com/document/d/11IoMKiohK7hIyIE36FJmwJv46DEBx52a4fqvrpCBBcg/edit?usp=sharing).

## OVN Kubernetes in a DPU-Accelerated Environment

The **ovn-kubernetes** deployment will have two parts one on the host and another on the DPU side.


These aforementioned parts are expected to be deployed also on two different Kubernetes clusters, one for the host and another for the DPUs.


### Host Cluster
---

#### OVN Kubernetes control plane related component
- ovn-cluster-manager

#### OVN Kubernetes components on a Standard Host (Non-DPU)
- local-nb-ovsdb
- local-sb-ovsdb
- run-ovn-northd
- ovnkube-controller-with-node
- ovn-controller
- ovs-metrics

#### OVN Kubernetes component on a DPU-Enabled Host
- ovn-node

For detailed configuration of gateway interfaces in DPU host mode, see [DPU Gateway Interface Configuration](dpu-gateway-interface.md).

### DPU Cluster
---

#### OVN Kubernetes components
- local-nb-ovsdb 
- local-sb-ovsdb
- run-ovn-northd
- ovnkube-controller-with-node
- ovn-controller
- ovs-metrics
