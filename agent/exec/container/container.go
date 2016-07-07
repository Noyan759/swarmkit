package container

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/docker/engine-api/types"
	enginecontainer "github.com/docker/engine-api/types/container"
	"github.com/docker/engine-api/types/events"
	"github.com/docker/engine-api/types/filters"
	"github.com/docker/engine-api/types/network"
	"github.com/docker/swarmkit/agent/exec"
	"github.com/docker/swarmkit/api"
)

const (
	// Explicitly use the kernel's default setting for CPU quota of 100ms.
	// https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt
	cpuQuotaPeriod = 100 * time.Millisecond

	// systemLabelPrefix represents the reserved namespace for system labels.
	systemLabelPrefix = "com.docker.swarm"
)

// containerConfig converts task properties into docker container compatible
// components.
type containerConfig struct {
	task *api.Task

	networksAttachments map[string]*api.NetworkAttachment
}

// newContainerConfig returns a validated container config. No methods should
// return an error if this function returns without error.
func newContainerConfig(t *api.Task) (*containerConfig, error) {
	var c containerConfig
	return &c, c.setTask(t)
}

func (c *containerConfig) setTask(t *api.Task) error {
	container := t.Spec.GetContainer()
	if container == nil {
		return exec.ErrRuntimeUnsupported
	}

	if container.Image == "" {
		return ErrImageRequired
	}

	// index the networks by name
	c.networksAttachments = make(map[string]*api.NetworkAttachment, len(t.Networks))
	for _, attachment := range t.Networks {
		c.networksAttachments[attachment.Network.Spec.Annotations.Name] = attachment
	}

	c.task = t
	return nil
}

func (c *containerConfig) endpoint() *api.Endpoint {
	return c.task.Endpoint
}

func (c *containerConfig) spec() *api.ContainerSpec {
	return c.task.Spec.GetContainer()
}

func (c *containerConfig) name() string {
	if c.task.Annotations.Name != "" {
		// if set, use the container Annotations.Name field, set in the orchestrator.
		return c.task.Annotations.Name
	}

	// fallback to service.instance.id.
	return strings.Join([]string{c.task.ServiceAnnotations.Name, fmt.Sprint(c.task.Slot), c.task.ID}, ".")
}

func (c *containerConfig) image() string {
	return c.spec().Image
}

func (c *containerConfig) config() *enginecontainer.Config {
	config := &enginecontainer.Config{
		Labels:     c.labels(),
		User:       c.spec().User,
		Env:        c.spec().Env,
		WorkingDir: c.spec().Dir,
		Image:      c.image(),
		Volumes:    c.volumes(),
	}

	if len(c.spec().Command) > 0 {
		// If Command is provided, we replace the whole invocation with Command
		// by replacing Entrypoint and specifying Cmd. Args is ignored in this
		// case.
		config.Entrypoint = append(config.Entrypoint, c.spec().Command...)
		config.Cmd = append(config.Cmd, c.spec().Args...)
	} else if len(c.spec().Args) > 0 {
		// In this case, we assume the image has an Entrypoint and Args
		// specifies the arguments for that entrypoint.
		config.Cmd = c.spec().Args
	}

	return config
}

func (c *containerConfig) hostConfig() *enginecontainer.HostConfig {
	hc := &enginecontainer.HostConfig{
		Resources: c.resources(),
		Binds:     c.binds(),
		Tmpfs:     c.tmpfs(),
	}

	if c.task.LogDriver != nil {
		hc.LogConfig = enginecontainer.LogConfig{
			Type:   c.task.LogDriver.Name,
			Config: c.task.LogDriver.Options,
		}
	}

	return hc
}

func (c *containerConfig) labels() map[string]string {
	var (
		system = map[string]string{
			"task":         "", // mark as cluster task
			"task.id":      c.task.ID,
			"task.name":    fmt.Sprintf("%v.%v", c.task.ServiceAnnotations.Name, c.task.Slot),
			"node.id":      c.task.NodeID,
			"service.id":   c.task.ServiceID,
			"service.name": c.task.ServiceAnnotations.Name,
		}
		labels = make(map[string]string)
	)

	// base labels are those defined in the spec.
	for k, v := range c.spec().Labels {
		labels[k] = v
	}

	// we then apply the overrides from the task, which may be set via the
	// orchestrator.
	for k, v := range c.task.Annotations.Labels {
		labels[k] = v
	}

	// finally, we apply the system labels, which override all labels.
	for k, v := range system {
		labels[strings.Join([]string{systemLabelPrefix, k}, ".")] = v
	}

	return labels
}

// volumes gets placed into the Volumes field on the containerConfig.
func (c *containerConfig) volumes() map[string]struct{} {
	r := make(map[string]struct{})
	// Volumes *only* creates anonymous volumes. The rest is mixed in with
	// binds, which aren't actually fucking binds. Basically, any volume that
	// results in a single component must be added here.
	//
	// This is reversed engineered from the behavior of the engine API.

	for _, spec := range c.bindsAndVolumes() {
		if len(spec) == 1 {
			r[strings.Join(spec, ":")] = struct{}{}
		}
	}

	return r
}

func (c *containerConfig) binds() []string {
	var r []string

	for _, spec := range c.bindsAndVolumes() {
		if len(spec) > 1 {
			r = append(r, strings.Join(spec, ":"))
		}
	}

	return r
}

func (c *containerConfig) tmpfs() map[string]string {
	r := make(map[string]string)

	for _, spec := range c.spec().Mounts {
		if spec.Type != api.MountTypeTmpfs {
			continue
		}

		r[spec.Target] = getMountMask(&spec)
	}

	return r
}

// bindsAndVolumes uses the list of mounts to create candidates for the Binds
// and Volumes. Effectively, we only use annonymous volumes in the volumes API
// and the rest becomes binds.`
func (c *containerConfig) bindsAndVolumes() [][]string {
	var specs [][]string
	for _, mount := range c.spec().Mounts {
		if mount.Type != api.MountTypeBind && mount.Type != api.MountTypeVolume {
			continue // skip tmpfs
		}

		var spec []string
		if mount.Source != "" {
			spec = append(spec, mount.Source)
		}

		spec = append(spec, mount.Target)

		mask := getMountMask(&mount)
		if mask != "" {
			spec = append(spec, mask)
		}

		specs = append(specs, spec)
	}

	return specs
}

func getMountMask(m *api.Mount) string {
	var maskOpts []string
	if m.ReadOnly {
		maskOpts = append(maskOpts, "ro")
	}

	switch m.Type {
	case api.MountTypeVolume:
		if m.VolumeOptions != nil && m.VolumeOptions.NoCopy {
			maskOpts = append(maskOpts, "nocopy")
		}
	case api.MountTypeBind:
		if m.BindOptions == nil {
			break
		}

		switch m.BindOptions.Propagation {
		case api.MountPropagationPrivate:
			maskOpts = append(maskOpts, "private")
		case api.MountPropagationRPrivate:
			maskOpts = append(maskOpts, "rprivate")
		case api.MountPropagationShared:
			maskOpts = append(maskOpts, "shared")
		case api.MountPropagationRShared:
			maskOpts = append(maskOpts, "rshared")
		case api.MountPropagationSlave:
			maskOpts = append(maskOpts, "slave")
		case api.MountPropagationRSlave:
			maskOpts = append(maskOpts, "rslave")
		}
	case api.MountTypeTmpfs:
		if m.TmpfsOptions == nil {
			break
		}

		if m.TmpfsOptions.Mode != 0 {
			maskOpts = append(maskOpts, fmt.Sprintf("mode=%o", m.TmpfsOptions.Mode))
		}

		if m.TmpfsOptions.SizeBytes != 0 {
			// calculate suffix here, making this linux specific, but that is
			// okay, since API is that way anyways.

			// we do this by finding the suffix that divides evenly into the
			// value, returing the value itself, with no suffix, if it fails.
			//
			// For the most part, we don't enforce any semantic to this values.
			// The operating system will usually align this and enforce minimum
			// and maximums.
			var (
				size   = m.TmpfsOptions.SizeBytes
				suffix string
			)
			for _, r := range []struct {
				suffix  string
				divisor int64
			}{
				{"g", 1 << 30},
				{"m", 1 << 20},
				{"k", 1 << 10},
			} {
				if size%r.divisor == 0 {
					size = size / r.divisor
					suffix = r.suffix
					break
				}
			}

			maskOpts = append(maskOpts, fmt.Sprintf("size=%d%s", size, suffix))
		}
	}

	return strings.Join(maskOpts, ",")
}

// This handles the case of volumes that are defined inside a service Mount
func (c *containerConfig) volumeCreateRequest(mount *api.Mount) *types.VolumeCreateRequest {
	var (
		driverName string
		driverOpts map[string]string
		labels     map[string]string
	)

	if mount.VolumeOptions != nil && mount.VolumeOptions.DriverConfig != nil {
		driverName = mount.VolumeOptions.DriverConfig.Name
		driverOpts = mount.VolumeOptions.DriverConfig.Options
		labels = mount.VolumeOptions.Labels
	}

	return &types.VolumeCreateRequest{
		Name:       mount.Source,
		Driver:     driverName,
		DriverOpts: driverOpts,
		Labels:     labels,
	}
}

func (c *containerConfig) resources() enginecontainer.Resources {
	resources := enginecontainer.Resources{}

	// If no limits are specified let the engine use its defaults.
	//
	// TODO(aluzzardi): We might want to set some limits anyway otherwise
	// "unlimited" tasks will step over the reservation of other tasks.
	r := c.task.Spec.Resources
	if r == nil || r.Limits == nil {
		return resources
	}

	if r.Limits.MemoryBytes > 0 {
		resources.Memory = r.Limits.MemoryBytes
	}

	if r.Limits.NanoCPUs > 0 {
		// CPU Period must be set in microseconds.
		resources.CPUPeriod = int64(cpuQuotaPeriod / time.Microsecond)
		resources.CPUQuota = r.Limits.NanoCPUs * resources.CPUPeriod / 1e9
	}

	return resources
}

func (c *containerConfig) virtualIP(networkID string) string {
	if c.task.Endpoint == nil {
		return ""
	}

	for _, vip := range c.task.Endpoint.VirtualIPs {
		// We only support IPv4 VIPs for now.
		if vip.NetworkID == networkID {
			vip, _, err := net.ParseCIDR(vip.Addr)
			if err != nil {
				return ""
			}

			return vip.String()
		}
	}

	return ""
}

func (c *containerConfig) networkingConfig() *network.NetworkingConfig {
	epConfig := make(map[string]*network.EndpointSettings)
	for _, na := range c.task.Networks {
		var ipv4, ipv6 string
		for _, addr := range na.Addresses {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}

			if ip.To4() != nil {
				ipv4 = ip.String()
				continue
			}

			if ip.To16() != nil {
				ipv6 = ip.String()
			}
		}

		epSettings := &network.EndpointSettings{
			IPAMConfig: &network.EndpointIPAMConfig{
				IPv4Address: ipv4,
				IPv6Address: ipv6,
			},
		}

		epConfig[na.Network.Spec.Annotations.Name] = epSettings
	}

	return &network.NetworkingConfig{EndpointsConfig: epConfig}
}

// networks returns a list of network names attached to the container. The
// returned name can be used to lookup the corresponding network create
// options.
func (c *containerConfig) networks() []string {
	var networks []string

	for name := range c.networksAttachments {
		networks = append(networks, name)
	}

	return networks
}

func (c *containerConfig) networkCreateOptions(name string) (types.NetworkCreate, error) {
	na, ok := c.networksAttachments[name]
	if !ok {
		return types.NetworkCreate{}, errors.New("container: unknown network referenced")
	}

	options := types.NetworkCreate{
		Driver: na.Network.DriverState.Name,
		IPAM: network.IPAM{
			Driver: na.Network.IPAM.Driver.Name,
		},
		Options:        na.Network.DriverState.Options,
		CheckDuplicate: true,
	}

	for _, ic := range na.Network.IPAM.Configs {
		c := network.IPAMConfig{
			Subnet:  ic.Subnet,
			IPRange: ic.Range,
			Gateway: ic.Gateway,
		}
		options.IPAM.Config = append(options.IPAM.Config, c)
	}

	return options, nil
}

func (c containerConfig) eventFilter() filters.Args {
	filter := filters.NewArgs()
	filter.Add("type", events.ContainerEventType)
	filter.Add("name", c.name())
	filter.Add("label", fmt.Sprintf("%v.task.id=%v", systemLabelPrefix, c.task.ID))
	return filter
}
